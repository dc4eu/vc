import Alpine from 'alpinejs';

/**
 * @typedef {Object} Schema
 * @property {string} name
 */

/**
 * @typedef {Object} Identity
 * @property {string} authentic_source_person_id
 * @property {Schema} schema
 * @property {string} family_name
 * @property {string} given_name
 * @property {string} birth_date - Format: YYYY-MM-DD
 * @property {string} birth_place
 * @property {string[]} nationality
 * @property {string} issuing_authority
 * @property {string} issuing_country
 * @property {string} expiry_date - Format: YYYY-MM-DD
 */

/**
 * @typedef {Object} GrantResponse
 * @property {boolean} grant
 * @property {Identity} identity
 * @property {string} redirect_url
 */

/**
 * @typedef {Object} UserData
 * @property {string} family_name
 * @property {string} given_name
 */

/**
 * @typedef {Object} SvgTemplate
 * @property {string} uri
 * @property {string} integrity
 */

/**
 * @typedef {Object} Claim
 * @property {string} id
 */

/**
 * @typedef {Object} Credential
 * @property {string} vct
 * @property {string} name
 * @property {SvgTemplate} svg_template
 * @property {Claim[]} claims
 */

const baseUrl = window.location.origin;

window.Alpine = Alpine;

Alpine.data("app", () => ({
    /** @type {GrantResponse | null} */
    grantResponse: null,

    /** @type {UserData | null} */
    userData: null,

    /** @type {boolean} */
    loggedIn: false,
    
    /** @type {string | null} */
    loginError: null,

    /** @param {SubmitEvent} event */
    async handleLogin(event) {
        this.loginError = null;

        const formData = new FormData(this.$refs.loginForm);

        const username = formData.get("username");
        if (!username) {
            this.loginError = "Username is required";
            return;
        }

        const password = formData.get("password");
        if (!password) {
            this.loginError = "Password is required";
            return;
        }

        console.info("Fetching credential offers for user:", username);

        const url = new URL("/user/pid/login", baseUrl);

        const options = {
            method: "POST", 
            headers: {
                "Accept": "application/json", 
                "Content-Type": "application/json; charset=utf-8",
            }, 
            body: JSON.stringify({
                username: username,
                password: password,
            }),
        };

        try {
            /** @type {GrantResponse} */ 
            const data = await this.fetchData(url, options);

            this.userData = {
                given_name: data.identity.given_name,
                family_name: data.identity.family_name,
                date_of_birth: data.identity.birth_date,
                expiry_date: data.identity.expiry_date,
            };

            this.grantResponse = data;

            this.$refs.title.innerText = `Welcome, ${this.userData.given_name}!`

            this.loggedIn = true;
        } catch (err) {
            this.loginError = "Failed to login: " + err.message;
        }
    },

    /** @param {SubmitEvent} event */
    handleCredentialSelection(event) {
        window.location.replace(this.grantResponse.redirect_url);
    },

    /** @param {Event} event */
    handleLogout(event) {
        this.loggedIn = null;
        this.userData = null;
    },

    /**
     * @param {RequestInfo} url 
     * @param {RequestInit} options 
     * @returns {Promise<any>}
     */
    async fetchData(url, options) {
        const response = await fetch(url, options);
        if (!response.ok) {
            if (response.status === 401) {
                this.userData = null;
                this.loggedIn = false;

                throw new Error("Unauthorized/session expired");
            }
            throw new Error(`HTTP error! status: ${response.status}, method: ${response.method}, url: ${url}`);
        }

        const data = await response.json();
        console.info(JSON.stringify(data, null, 2));
        return data;
    },

}));

Alpine.start();
