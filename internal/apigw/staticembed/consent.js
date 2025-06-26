import Alpine from 'alpinejs';
import * as v from "valibot";

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
 * @typedef {Object} SvgTemplateResponse
 * @property {string} template
 * @property {Record<string, string[]>} svg_claims
 */

/**
 * @typedef {Object} Credential
 * @property {string} document_type
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

const baseUrl = window.location.origin;

const ROUTES = {
    login: "#/",
    success: "#/success"
}

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

    /** @type {number | null} */
    pidAuthRedirectCountUp: null,

    /** @type {number} */
    pidAuthRedirectMaxCount: 7,

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

        this.authMethod = authMethod;

        this.hashState();

        this.$watch("error", (newVal) => {
            if (typeof newVal === "string") {
                console.error(`Error: ${newVal}`);
            }
        });

        if (this.loggedIn) {
            this.handleIsLoggedIn();
        }
        this.$watch("loggedIn", (newVal) => {
            if (newVal) {
                this.handleIsLoggedIn();
            }
        });

        this.loading = false;
    },

    hashState() {
        /** @param {string} hash */
        const updateLoginState = (hash) => {
            this.loggedIn = (hash === ROUTES.success);
        };

        updateLoginState(window.location.hash);

        addEventListener("hashchange", (event) => {
            this.loading = true;
            const { hash } = new URL(event.newURL);
            updateLoginState(hash);
            this.loading = false;
        });
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
            const BasicAuthResponseSchema = v.required(v.object({
                grant: v.boolean(),
                redirect_url: v.pipe(
                    v.string(),
                    v.url(),
                )
            }))

            const res = await this.fetchData(url.toString(), options);

            const data = v.parse(BasicAuthResponseSchema, res);

            console.log(data)

            // this.grantResponse = data;

            // const claims = {
            //     given_name: data.pid.identity.given_name,
            //     family_name: data.pid.identity.family_name,
            //     birth_date: data.pid.identity.birth_date,
            //     expiry_date: data.pid.identity.expiry_date,
            // };

            // const svg = await this.createCredentialSvgImageUri(
            //     claims,
            // );

            // this.credentials.push({
            //     document_type: data.pid.document_type,
            //     name: "PID",
            //     svg,
            //     claims,
            // });

            // this.$refs.title.innerText = `Welcome, ${data.pid.identity.given_name}!`

            window.location.hash = ROUTES.success;
        } catch (err) {
            if (err instanceof v.ValiError) {
                this.error = err.message;
            } else {
                this.error = `Failed to login: ${err.message}`;
            }
            this.loggedIn = false;
            this.loading = false;
        }
    },

    /**
     * @param {boolean} immediate - Immediately proceed to 'redirect_uri'
     */
    handleLoginPidAuth(immediate = false) {
        const rawRedirectUrl = getCookie("pid_auth_redirect_url");
        if (!rawRedirectUrl) {
            this.error = "Missing 'pid_auth_redirect_url' cookie";
            return;
        }

        try {
            const url = decodeURIComponent(rawRedirectUrl);

            if (immediate) {
                this.redirect(url);
                return;
            }

            this.pidAuthRedirectCountUp = 1;

            const increment = setInterval(() => {
                // We can stop the interval by setting
                // this.pidAuthRedirectCountUp to 'null'
                if (!this.pidAuthRedirectCountUp) {
                    clearInterval(increment);
                    return;
                }

                ++this.pidAuthRedirectCountUp;

                if (this.pidAuthRedirectCountUp >= this.pidAuthRedirectMaxCount) {
                    clearInterval(increment);
                    this.redirect(url);
                    return;
                }
            }, 1000);

        } catch (err) {
            if (err instanceof URIError) {
                this.error = `Invalid redirect_uri provided: ${err.message}`;
            } else {
                this.error = err.message;
            }

            this.pidAuthRedirectCountUp = null;
        }
    },

    async handleIsLoggedIn() {
        this.loading = true;

        const url = new URL("/user/lookup", baseUrl);

        const options = {
            method: "GET", 
            headers: {
                "Accept": "application/json", 
                "Content-Type": "application/json; charset=utf-8",
            }, 
        };

        try {
            const UserLookupResponseSchema = v.required(v.object({
                svg_template_claims: v.object({
                    given_name: v.string(),
                    family_name: v.string(),
                    birth_date: v.string(),
                }),
            }));

            const res = await this.fetchData(url.toString(), options);

            const data = v.parse(UserLookupResponseSchema, res);

            console.log(data)

        } catch (err) {
            if (err instanceof v.ValiError) {
                this.error = err.message;
            } else {
                this.error = `Error: ${err.message}`;
            }
            this.loggedIn = false;
        }

        this.loading = false;
    },

    /** @param {SubmitEvent} event */
    handleCredentialSelection(event) {
        if (!this.grantResponse) {
            console.error("Fatal: 'grantResponse' is null");
            return;
        }
        this.redirect(this.grantResponse.redirect_url);
    },

    /** @param {Event} event */
    handleLogout(event) {
        window.location.reload();
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
     * @param {Record<string, string>} claims
     * @returns {Promise<string>}
     */
    async createCredentialSvgImageUri(claims) {
        const url = new URL('/authorization/consent/svg-template', baseUrl);

        /** @type {SvgTemplateResponse} */
        const data = await this.fetchData(url.toString(), {});

        let svg = atob(data.template);

        for (const [svg_id, paths] of Object.entries(data.svg_claims)) {
            let newVal = "";

            for (const path of paths) {
                if (path in claims && typeof claims[path] === "string") {
                    newVal = claims[path];
                    break;
                }
            }

            svg = svg.replaceAll(`{{${svg_id}}}`, newVal);
        }

        return `data:image/svg+xml;base64,${btoa(svg)}`;
    },

    /** @param {string} url */
    redirect(url) {
        this.loading = true;

        try {
            window.location.href = (new URL(url)).toString();
        } catch (err) {
            this.error = `Error when redirecting: ${err}`;
        }
    },
}));

Alpine.start();
