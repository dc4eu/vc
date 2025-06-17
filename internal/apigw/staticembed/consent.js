const baseUrl = window.location.origin;

const validateHasValueAndNotEmpty = (element) => {
    return element?.value?.trim().length > 0;
};

const hideElement = (elementId) => {
    const element = document.getElementById(elementId);
    if (element === null) {
        console.error("element not found for id: " + elementId);
        return;
    }
    if (!element.classList.contains("is-hidden")) {
        element.classList.add("is-hidden");
    }
};

const showElement = (elementId) => {
    const element = document.getElementById(elementId);
    if (element === null) {
        console.error("element not found for id: " + elementId);
        return;
    }
    if (element.classList.contains("is-hidden")) {
        element.classList.remove("is-hidden");
    }
};

const clearInnerElementsOf = (elementId) => {
    const element = document.getElementById(elementId);
    if (element === null) {
        console.error("element not found for id: " + elementId);
        return;
    }
    while (element.firstChild) {
        element.removeChild(element.firstChild);
    }
};

const isEmptyObject = (obj) => {
    return obj && Object.keys(obj).length === 0 && obj.constructor === Object;
};


const displayError = (errorText) => {
    const pError = document.createElement("p");
    pError.innerText = errorText;
    pError.classList.add("has-text-danger");
    document.getElementById("error_container").appendChild(pError);
}

const doLogin = () => {
    const usernameElement = document.getElementById("username");
    const passwordElement = document.getElementById("password");

    clearInnerElementsOf("error_container");
    if (!validateHasValueAndNotEmpty(usernameElement) || !validateHasValueAndNotEmpty(passwordElement)) {
        displayError("Empty username and/or password");
        return;
    }

    const username = usernameElement.value;
    const password = passwordElement.value;
    usernameElement.value = "";
    passwordElement.value = "";

    console.info("Fetching credential offers for user:", username);

    const url = new URL("/user/pid/login", baseUrl);
    const headers = {
        'Accept': 'application/json', 'Content-Type': 'application/json; charset=utf-8',
    };
    const requestBody = {
        username: username,
        password: password,
    };
    const options = {
        method: `POST`, headers: headers, body: JSON.stringify(requestBody),
    };

    fetchData(url, options).then(data => {
        showElement("logout_container");
        hideElement("login_container");
        selectPID(data, username);
    }).catch(err => {
        displayError("Failed to login: ");
    });
};

const doLogout = () => {
    hideElement("logout_container");
    clearInnerElementsOf("error_container");
    showElement("login_container");
    clearInnerElementsOf("qr_container");
    document.getElementById('username').focus();
};


async function fetchData(url, options) {
    const response = await fetch(url, options);
    if (!response.ok) {
        if (response.status === 401) {
            hideElement("logout_container");
            clearInnerElementsOf("error_container");
            clearInnerElementsOf("qr_container");
            showElement("login_container");

            throw new Error("Unauthorized/session expired");
        }
        throw new Error(`HTTP error! status: ${response.status}, method: ${response.method}, url: ${url}`);
    }

    const data = await response.json();
    console.info(JSON.stringify(data, null, 2));
    return data;
}

function safeReplace(input, toReplace, replacement) {
    if (typeof input !== "string") return "";
    if (typeof toReplace !== "string" || toReplace === "") return input;
    if (!input.includes(toReplace)) return input;
    return input.replace(toReplace, replacement);
}

function buildLink({href, text, title = href, target = "_blank", className = "is-Link"}) {
    const link = document.createElement('a');
    link.href = href;
    link.title = title;
    link.textContent = text;
    link.target = target;
    link.classList.add(className);
    return link;
}

function selectPID(data, username) {
    if (data.grant) {
        const qrContainer = document.getElementById("qr_container");
        window.location.replace(data.redirect_url);
    }
    const textBusinessDecisionFor = document.createTextNode("Credential offers for ");
}

document.addEventListener('DOMContentLoaded', function () {
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const loginButton = document.getElementById('do-login-btn');

    function handleEnterKey(event) {
        if (event.key === 'Enter') {
            loginButton.click();
        }
    }

    usernameInput.focus();
    usernameInput.addEventListener('keydown', handleEnterKey);
    passwordInput.addEventListener('keydown', handleEnterKey);

    loginButton.addEventListener('click', function () {
        doLogin();
    });

    const logoutButton = document.getElementById("do-logout-btn");
    logoutButton.addEventListener('click', function () {
        doLogout();
    });
});