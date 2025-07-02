import Alpine from "alpinejs";
import * as v from "valibot";


const CredentialSchema = v.object({
  name: v.string(),
  description: v.string()
});

/**
 * @typedef {v.InferOutput<typeof OffersLookupSchema>} OffersLookup
 */
const OffersLookupSchema = v.required(v.object({
    credentials: v.record(v.string(), CredentialSchema),
    wallets: v.record(v.string(), v.string())
}))

/**
 * @typedef {v.InferOutput<typeof CredentialOfferSchema>} CredentialOffer
 */
const CredentialOfferSchema = v.required(v.object({
    name: v.string(),
    id: v.string(),
    qr: v.object({
        base64_image: v.string(),
        uri: v.string(),
    }),
}));

Alpine.data("app", () => ({
    credentials: null,
    wallets: null,

    /** @type {CredentialOffer} */
    credentialOffer: null,

    /** @type {boolean} */
    loading: true,

    /** @type {string | null} */
    error: null,

    async init() {
        await this.lookupOffers()

        this.loading = false;

        this.$watch("error", (newVal) => {
            if (typeof newVal === "string") {
                console.error(`Error: ${newVal}`);
            }
        });

        await this.hashState();

    },

    async hashState() {
        /** @param {string} hash */
        const refreshState = async (hash) => {
            const state = new URLSearchParams(hash.slice(1));

            if (state.has("scope") && state.has("wallet_id")) {
                await this.getOfferData(state.get("scope"), state.get("wallet_id"))
            } else {
                await this.lookupOffers();
            }
        };

        await refreshState(location.hash)

        addEventListener("hashchange", async () => {
            this.loading = true;
            
            await refreshState(location.hash)
            
            this.loading = false;
        });
    },

    /**
     * @param {SubmitEvent} event 
     */
    async handleOffersForm(event) {
        this.error = null;
        this.loading = true;
        this.credentials = null;
        this.wallets = null;

        if (!(this.$refs.offersForm instanceof HTMLFormElement)) {
            this.error = "Offers form not of type 'HtmlFormElement'";
            return;
        }

        const formData = new FormData(this.$refs.offersForm);

        const credential = formData.get("credential");
        if (!credential) {
            this.error = "Credential is required";
            return;
        }

        const wallet = formData.get("wallet");
        if (!wallet) {
            this.error = "Wallet is required";
            return;
        }

        window.location.hash = `scope=${credential}&wallet_id=${wallet}`;
    },

    async lookupOffers() {
        try {
            this.credentialOffer = null;

            const res = await fetch("/offers/lookup");
            if (!res.ok) {
                this.error = "Failed to fetch credential offers";
                return;
            }

            const data = v.parse(OffersLookupSchema, (await res.json()));

            this.credentials = data.credentials;
            this.wallets = data.wallets;
        } catch (err) {
            this.error = err;
        }
    },

    async getOfferData(credential, wallet) {
        try {
            const res = await fetch(`/offers/${credential}/${wallet}`)
            if (!res.ok) {
                this.error = "Failed to fetch credential offer";
                return;
            }

            const data = v.parse(CredentialOfferSchema, (await res.json()));

            this.credentialOffer = data;
        } catch (err) {
            this.error = err;
        }
    },

    handleCredentialOfferProceed() {
        if (this.credentialOffer) {
            window.location.href = this.credentialOffer.qr.uri;
        }
    }
}));

Alpine.start();
