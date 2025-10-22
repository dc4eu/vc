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

/** @typedef {v.InferOutput<typeof credentialAttributesMapSchema>} CredentialAttributesMap */
const credentialAttributesMapSchema = v.record(
    v.string(),
    credentialAttributesSchema,
);

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

    /** @type {CredentialAttributesMap | null} */
    credentialAttributesMap: null,

     /** @type {CredentialAttributes | null} */
    selectedCredentialAttributes: null,

    /** @type {string | null} */
    error: null,

    async init() {
        await this.lookupCredentialAttributes();
        this.loading = false;

        this.$watch("error", (newVal) => {
            if (typeof newVal === "string") {
                console.error(`Error: ${newVal}`);
            }
        });
      
    },

    async lookupCredentialAttributes() {
        const res = await this.fetchData(new URL("/credential/attributes", baseUrl), {});

        const data = v.parse(credentialAttributesMapSchema, res);

        this.credentialAttributesMap = data;
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

        if (!this.credentialAttributesMap || !this.credentialAttributesMap[credential]) {
            this.error = "Credential is missing or invalid";
            return;
        }

        this.selectedCredentialAttributes = this.credentialAttributesMap[credential];

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

    selectNoneAttributes() {

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
