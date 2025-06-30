import Alpine from "alpinejs";
import * as v from "valibot";

/**
 * @typedef {Object} Credential
 * @property {string} document_type
 * @property {string} name
 * @property {string} svg
 * @property {Record<string, string>} claims
 */

/**
 * @typedef {v.InferOutput<typeof SvgTemplateResponseSchema>} SvgTemplateResponse
 */
const SvgTemplateResponseSchema = v.required(v.object({
    template: v.string(),
    svg_claims: v.record(v.string(), v.array(v.string())),
}));

/**
 * @typedef {v.InferOutput<typeof BasicAuthResponseSchema>} BasicAuthResponse
 */
const BasicAuthResponseSchema = v.required(v.object({
    grant: v.boolean(),
    redirect_url: v.pipe(
        v.string(),
        v.url(),
    )
}));

/**
 * @typedef {v.InferOutput<typeof UserDataSchema>} UserData
 */
const UserDataSchema = v.required(v.object({
    svg_template_claims: v.object({
        given_name: v.string(),
        family_name: v.string(),
        birth_date: v.string(),
    }),
}));

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
 * @param {string} key 
 * @returns {string}
 */
function keyToLabel(key) {
    if (key.includes("_")) {
        let parts = key.split("_");

        parts[0] = parts[0].charAt(0).toUpperCase() + parts[0].slice(1);

        key = parts.join(" ");
    }

    return key;
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
    credentials: "#/credentials"
}

Alpine.data("app", () => ({
    /** @type {boolean} */
    loading: true,

    /** @type {string | null} */
    redirectUrl: null,

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
        this.setAuthMethod();

        this.hashState();

        this.$watch("error", (newVal) => {
            if (typeof newVal === "string") {
                console.error(`Error: ${newVal}`);
            }
        });

        if (this.loggedIn) {
            this.handleIsLoggedIn();
        } else {
            this.loading = false;
        }

        this.$watch("loggedIn", (newVal) => {
            if (newVal) {
                this.handleIsLoggedIn();
            } else {
                this.handleIsNotLoggedIn();
            }
        });
    },

    setAuthMethod() {
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
    },

    hashState() {
        /** @param {string} hash */
        const updateLoginState = (hash) => {
            this.loggedIn = (hash === ROUTES.credentials);
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
            const res = await this.fetchData(url.toString(), options);

            const data = v.parse(BasicAuthResponseSchema, res);

            this.redirectUrl = data.redirect_url;

            window.location.hash = ROUTES.credentials;
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

    async handleIsNotLoggedIn() {
        this.credentials = [];
        this.$refs.title.innerText = "Authorization Consent";
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
            const res = await this.fetchData(url.toString(), options);

            const data = v.parse(UserDataSchema, res);

            const svg = await this.createCredentialSvgImageUri(
                data.svg_template_claims,
            );

            /** @type {Record<string, string>} */
            let claims = {};

            for (let [key, value] of Object.entries(data.svg_template_claims)) {
                key = keyToLabel(key);

                claims[key] = value;
            }

            this.credentials.push({
                document_type: "N/A",
                name: "PID",
                svg,
                claims,
            });

            this.$refs.title.innerText = `Welcome, ${data.svg_template_claims.given_name}!`
        } catch (err) {
            if (err instanceof v.ValiError) {
                this.error = err.message;
            } else {
                this.error = `Error: ${err.message}`;
            }
            window.location.hash = ROUTES.login;
        } finally {
            this.loading = false;
        }
    },

    /** @param {SubmitEvent} event */
    handleCredentialSelection(event) {
        if (!this.redirectUrl) {
            this.error = "'redirectUrl' is null";
        }
        this.redirect(this.redirectUrl);
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
                this.redirectUrl = null;
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
        const url = new URL("/authorization/consent/svg-template", baseUrl);

        const res = await this.fetchData(url.toString(), {});

        const data = v.parse(SvgTemplateResponseSchema, res);

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
