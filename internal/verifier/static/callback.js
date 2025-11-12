import Alpine from "alpinejs";
import * as v from "valibot";


const baseUrl = new URL(window.location.origin);

Alpine.data("app", () => ({
    /** @type {boolean} */
    loading: true,

    /** @type {string | null} */
    error: null,

    async init() {
        this.loading = false;

        this.$watch("error", (newVal) => {
            if (typeof newVal === "string") {
                console.error(`Error: ${newVal}`);
            }
        });

    },

    getResponseCode() {
        const params = new URLSearchParams(document.location.search);
        const responseCode = params.get("response_code");
        if (!responseCode) {
            this.error = "Missing url param 'response_code'";
            return;
        }

        return responseCode;
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
