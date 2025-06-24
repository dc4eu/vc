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
 * @typedef {Object} PID
 * @property {Identity} identity
 * @property {string} document_type
 * @property {string} authentic_source
 */

/**
 * @typedef {Object} GrantResponse
 * @property {boolean} grant
 * @property {PID} pid
 * @property {string} redirect_url
 */

/**
 * @typedef {Object} SvgTemplate
 * @property {string} uri
 * @property {string} integrity
 */

/**
 * @typedef {Object} Credential
 * @property {string} vct
 * @property {string} name
 * @property {string} svg
 * @property {Record<string, string>} claims
 */

/**
 * @param {string} name 
 * @returns {string | null}
 */
function getCookie(name) {
    return document.cookie
        .split(";")
        .find((cookie) =>
            cookie.trim().startsWith(`${name}=`),
        )
        ?.split("=")
        .pop() || null;
}

const baseUrl = window.location.origin;

Alpine.data("app", () => ({
    /** @type {boolean} */
    loading: true,

    /** @type {GrantResponse | null} */
    grantResponse: null,

    /** @type {Credential[]} */
    credentials: [],

    /** @type {boolean} */
    loggedIn: false,

    /** @type {"basic" | "pid_auth" | null} */
    authMethod: null,

    /** @type {string | null} */
    error: null,

    init() {
        const authMethod = getCookie("auth_method");

        if (
            !authMethod ||
            authMethod !== "basic" &&
            authMethod !== "pid_auth"
        ) {
            this.error = `Unknown auth method: '${authMethod}'`;
            return;
        }

        this.authMethod = authMethod

        this.loading = false;

        this.$watch("error", (newVal) => {
            if (typeof newVal === "string") {
                console.error(`Error: ${newVal}`);
            }
        })
    },

    /** @param {SubmitEvent} event */
    async handleLoginBasic(event) {
        this.loading = true;
        this.error = null;

        if (!(this.$refs.loginForm instanceof HTMLFormElement)) {
            this.error = "Login form not of type 'HtmlFormElement'";
            return;
        }

        const formData = new FormData(this.$refs.loginForm);

        const username = formData.get("username");
        if (!username) {
            this.error = "Username is required";
            return;
        }

        const password = formData.get("password");
        if (!password) {
            this.error = "Password is required";
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
            const data = await this.fetchData(url.toString(), options);

            this.grantResponse = data;

            const claims = {
                given_name: data.pid.identity.given_name,
                family_name: data.pid.identity.family_name,
                birth_date: data.pid.identity.birth_date,
                expiry_date: data.pid.identity.expiry_date,
            };

            const svg = await this.createCredentialSvgImageUri(
                {
                    uri: new URL("/static/person-identification-data-svg-example-01.svg", baseUrl).toString(),
                    integrity: "sha256-037rNwIiS/qeKc16yxy3xJlAYYFGul1wJAcGjXjDVLw="
                },
                claims,
            );

            this.credentials.push({
                vct: "urn:eudi:pid:1",
                name: "PID",
                svg,
                claims,
            });

            this.$refs.title.innerText = `Welcome, ${data.pid.identity.given_name}!`

            this.loggedIn = true;
            this.loading = false;
        } catch (err) {
            this.error = `Failed to login:`;
            this.loading = false;
        }
    },

    /** @param {SubmitEvent} event */
    handleCredentialSelection(event) {
        if (!this.grantResponse) {
            console.error("Fatal: 'grantResponse' is null");
            return;
        }
        window.location.replace(this.grantResponse.redirect_url);
    },

    /** @param {Event} event */
    handleLogout(event) {
        this.loggedIn = false;
        this.$refs.title.innerHTML = "Authorize Consent";
        this.grantResponse = null;
        this.credentials = [];
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
                this.loggedIn = false;
                this.grantResponse = null;
                this.credentials = [];

                throw new Error("Unauthorized/session expired");
            }
            throw new Error(`HTTP error! status: ${response.status}, url: ${url}`);
        }

        const data = await response.json();
        console.info(JSON.stringify(data, null, 2));
        return data;
    },

    /**
     * @param {SvgTemplate} svg_template
     * @param {Record<string, string>} claims
     * @returns {Promise<string>}
     */
    async createCredentialSvgImageUri(svg_template, claims) {
        const res = await fetch(svg_template.uri);
        let svg = await res.text();

        for (let [key, value] of Object.entries(claims)) {
            svg = svg.replaceAll(`{{${key}}}`, value);
        }

        return `data:image/svg+xml;base64,${btoa(svg)}`;
    }
}));

Alpine.start();
