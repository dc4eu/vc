import Alpine from "alpinejs";
import * as v from "valibot";

/** @typedef {v.InferOutput<typeof credentialAttributesSchema>} CredentialAttributes */
const credentialAttributesSchema = v.object({
    vct: v.string(),
    vctm_file_path: v.string(),
    auth_method: v.string(),
    attributes_v2: v.record(
        v.string(),
        v.record(
            v.string(),
            v.array(v.string()),
        ),
    ),
});

/** @typedef {v.InferOutput<typeof credentialsList>} CredentialsList */
const credentialsList = v.record(
    v.string(),
    credentialAttributesSchema,
);

/** @typedef {v.InferOutput<typeof metadataResponseSchema>} MetadataResponse */
const metadataResponseSchema = v.object({
    credentials: credentialsList,
    supported_wallets: v.record(v.string(), v.string()),
})

/** @typedef {v.InferOutput<typeof dcqlQueryCredentialSchema>} DCQLQueryCredential */
const dcqlQueryCredentialSchema = v.object({
    id: v.string(),
    format: v.union([
        v.literal("vc+sd-jwt"),
    ]),
    meta: v.intersect([
        v.object({
            vct_values: v.array(v.string()),
        }),
        v.record(v.string(), v.union([v.string(), v.array(v.string())])),
    ]),
    claims: v.array(v.object({
        path: v.array(v.string()),
    })),
});

/** @typedef {v.InferOutput<typeof dcqlQuerySchema>} DCQLQuery */
const dcqlQuerySchema = v.object({
    credentials: v.array(dcqlQueryCredentialSchema),
});

/** @typedef {v.InferOutput<typeof presentationDefinitionSchema>} PresentationDefinition */
const presentationDefinitionSchema = v.object({
    qr_code: v.string(),
    authorization_request: v.string(),
});

/**
 * Due to bfcache some state will persist across
 * navigation events, so we 'manually' clear it.
 * @see https://developer.mozilla.org/en-US/docs/Glossary/bfcache
 */
window.addEventListener("pageshow", (event) => {
    if (event.persisted) {
        window.location.reload();
    }
});

const baseUrl = new URL(window.location.origin);

Alpine.data("app", () => ({
    /** @type {boolean} */
    loading: true,

    /** @type {string | null} */
    error: null,

    /** @type {CredentialsList | null} */
    credentialsList: null,

    /** @type {Record<string, string> | null} */
    walletInstances: null,

     /** @type {{ id: string; vct: string; claims: Record<string, string[]>; } | null} */
    credentialAttributes: null,

    /** @type {DCQLQuery | null} */
    dcqlQuery: null,

    /** @type {PresentationDefinition | null} */
    presentationDefinition: null,

    /** @type {Record<string, string> | null} */
    redirectUris: null,

    async init() {
        await this.lookupCredentialsList();
        this.loading = false;

        this.$watch("error", (newVal) => {
            if (typeof newVal === "string") {
                console.error(`Error: ${newVal}`);
            }
        });
      
    },

    async lookupCredentialsList() {
        const res = await this.fetchData(new URL("/ui/metadata", baseUrl), {});

        const data = v.parse(metadataResponseSchema, res);

        this.credentialsList = data.credentials;
        this.walletInstances = data.supported_wallets;
    },

    /** @param {SubmitEvent} event */
    handleCredentialSelectionForm(event) {
        this.error = null;
        this.loading = true;

        if (!(this.$refs.credentialSelectionForm instanceof HTMLFormElement)) {
            this.error = "Credential Selection form not of type 'HtmlFormElement'";
            return;
        }

        const formData = new FormData(this.$refs.credentialSelectionForm);

        const credential = formData.get("credential")?.toString();
        if (!credential) {
            this.error = "Credential is required";
            return;
        }

        if (!this.credentialsList || !this.credentialsList[credential]) {
            this.error = "Credential is missing or invalid";
            return;
        }

        const chosenCredential = this.credentialsList[credential];

        /** @type {Record<string, string[]>} */
        const claims = {}
        for (const [label, path] of Object.entries(chosenCredential.attributes_v2['en-US'])) {
            claims[label] = path;
        }

        this.credentialAttributes = {
            id: credential,
            vct: chosenCredential.vct,
            claims,
        }

        this.loading = false;
    },

    /** @param {'all'|'none'} mode */
    handleAttributesToggle(mode) {
        if (!(this.$refs.fieldsList instanceof HTMLElement)) {
            this.error = "Fields list form not of type 'HTMLElement'";
            return;
        }

        return () => {
            /** @type {NodeListOf<HTMLInputElement>} */
            const inputs = this.$refs.fieldsList.querySelectorAll("input[type='checkbox']");

            for (const input of Array.from(inputs)) {
                input.checked = mode === "all";
            }
        }
    },

    handleResetCancel() {
        this.credentialAttributes = null;
        this.dcqlQuery = null;
        this.presentationDefinition = null;
    },

    /** @param {SubmitEvent} event */
    async handleAttributesSelectionForm(event) {
        this.error = null;
        this.loading = true;

        if (!this.credentialAttributes) {
            this.error = "Selected attributes list is null";
            return;
        }

        if (!this.walletInstances) {
            this.error = "Wallet instances list is null";
            return;
        }
        
        if (!(this.$refs.attributesSelectionForm instanceof HTMLFormElement)) {
            this.error = "Attributes selection form not of type 'HtmlFormElement'";
            return;
        }

        const formData = new FormData(this.$refs.attributesSelectionForm);

        /** @type {DCQLQueryCredential["claims"]} */
        const claims = [];
        for (const field of formData.getAll("attribute[]")) {
            const path = this.credentialAttributes.claims[field.toString()];

            if (!path) continue;

            claims.push({ path });
        }

        /** @satisfies {DCQLQueryCredential} */
        const credential = {
            id: this.credentialAttributes.id,
            format: "vc+sd-jwt",
            meta: {
                vct_values: [this.credentialAttributes.vct]
            },
            claims,
        };

        /** @satisfies {DCQLQuery} */
        const dcqlQuery = {
            credentials: [credential],
        };

        const { output: dcql_query, success } = v.safeParse(dcqlQuerySchema, dcqlQuery);
        if (!success) {
            this.error = "Invalid DCQL query";
            return;
        }

        this.dcqlQuery = dcql_query;

        try {
            const res = await this.fetchData(
                new URL("/ui/interaction", baseUrl), 
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({
                        dcql_query,
                    })
                },
            );

            this.presentationDefinition = v.parse(presentationDefinitionSchema, res);

            const presDefURI = new URL(this.presentationDefinition.authorization_request);

            for (const [label, url] of Object.entries(this.walletInstances)) {
                const uri = new URL(url);

                uri.search = presDefURI.search
                uri.hash = presDefURI.hash

                if (!this.redirectUris) this.redirectUris = {};

                this.redirectUris[`Open with ${label}`] = uri.toString();
            }
        } catch (error) {
            this.error = `Error during posting of dcql query: ${error}`;
            return;
        }

        this.loading = false;
    },

    /**
     * @param {RequestInfo|URL} url 
     * @param {RequestInit} options 
     * @returns {Promise<any>}
     */
    async fetchData(url, options) {
        if (url instanceof URL) url = url.toString();
        const response = await fetch(url, options);
        if (!response.ok) {
            if (response.status === 401) {
                throw new Error("Unauthorized/session expired");
            }
            throw new Error(`HTTP error! status: ${response.status}, url: ${url}`);
        }

        const data = await response.json();
        console.debug(JSON.stringify(data, null, 2));
        return data;
    },
}));

Alpine.start();
