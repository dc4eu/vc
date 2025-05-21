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

    const url = new URL("/secure/apigw/user/credential-offers", baseUrl);
    const headers = {
        'Accept': 'application/json', 'Content-Type': 'application/json; charset=utf-8',
    };
    const requestBody = {
        // family_name: username,
        // limit: 100,
        // fields: ["meta.document_id", "meta.authentic_source", "meta.document_type", "meta.collect.id", "identities", "qr"],
        username: username,
        password: password,
    };
    const options = {
        method: `POST`, headers: headers, body: JSON.stringify(requestBody),
    };
    console.debug(url, options);

    fetchData(url, options).then(data => {
        showElement("logout_container");
        hideElement("login_container");
        displayQrCodes(data, username);
    }).catch(err => {
        console.debug("Unexpected error:", err);
        displayError("Failed to fetch credential-offers: " + err);
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
    //console.debug(JSON.stringify(data, null, 2));
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

function displayQrCodes(data, username) {
    console.debug("Data received:", data);

    const qrContainer = document.getElementById("qr_container");

    const usernameStrong = document.createElement("strong");
    usernameStrong.appendChild(document.createTextNode(username));

    const textBusinessDecisionFor = document.createTextNode("Credential offers for ");

    const pQrHeader = document.createElement("p");
    pQrHeader.classList.add("subtitle", "is-5", "has-text-centered");
    pQrHeader.appendChild(textBusinessDecisionFor);
    pQrHeader.appendChild(usernameStrong);

    qrContainer.appendChild(pQrHeader);

    if (isEmptyObject(data) || (Array.isArray(data.documents) && data.documents.length === 0)) {
        console.debug("No credential offers found");
        let p = document.createElement("p");
        p.classList.add("has-text-centered");
        p.innerText = "No credential offers found";
        qrContainer.appendChild(p);
        return;
    }

    const gridDiv = document.createElement("div");
    gridDiv.classList.add("grid");

    const fixedGridDiv = document.createElement("div");
    fixedGridDiv.classList.add("fixed-grid");
    fixedGridDiv.appendChild(gridDiv);


    const br = document.createElement("br");

    data.documents.forEach((doc) => {

        const credentialOfferUrl = doc.qr?.credential_offer_url || "";

        const cell1 = document.createElement("div");
        cell1.classList.add("cell");

        if (doc.qr?.qr_base64 && credentialOfferUrl !== "") {
            const img = document.createElement("img");
            img.src = `data:image/png;base64,${doc.qr.qr_base64}`;

            const a = document.createElement("a");
            const credentialOfferUrl = doc.qr.credential_offer_url;
            a.href = credentialOfferUrl;
            a.target = "_blank";
            a.title = credentialOfferUrl;
            a.appendChild(img);
            cell1.appendChild(a);
        } else {
            const pQrNotFound = document.createElement("p");
            pQrNotFound.innerText = "No qr code found in document";
            cell1.appendChild(pQrNotFound);
        }

        const cell2 = document.createElement("div");
        cell2.classList.add("cell", "has-text-left");

        const boldText = document.createElement("b");
        boldText.textContent = doc.meta?.document_type || "";
        cell2.appendChild(boldText);

        const pAS = document.createElement("p");
        pAS.innerText = "Authentic source: " + doc.meta?.authentic_source || "";
        cell2.appendChild(pAS);

        const pDocId = document.createElement("p");
        pDocId.innerText = "Document ID: " + doc.meta?.document_id || "";
        cell2.appendChild(pDocId);

        const pColId = document.createElement("p");
        pColId.innerText = "Collect ID: " + doc.meta?.collect?.id || "";
        cell2.appendChild(pColId);

        if (credentialOfferUrl !== "") {
            const toReplace = "openid-credential-offer://?";
            cell2.appendChild(buildLink({
                href: safeReplace(credentialOfferUrl, toReplace, "https://dc4eu.wwwallet.org/cb?"),
                text: "DC4EU wallet",
            }));
            cell2.appendChild(document.createElement("br"));
            cell2.appendChild(buildLink({
                href: safeReplace(credentialOfferUrl, toReplace, "https://demo.wwwallet.org/cb?"),
                text: "Demo DC4EU wallet",
            }));
            cell2.appendChild(document.createElement("br"));
            cell2.appendChild(buildLink({
                href: safeReplace(credentialOfferUrl, toReplace, "https://dev.wallet.sunet.se/cb?"),
                text: "Dev SUNET wallet",
            }));
            cell2.appendChild(document.createElement("br"));
            cell2.appendChild(buildLink({
                href: safeReplace(credentialOfferUrl, toReplace, "https://funke.wwwallet.org/cb?"),
                text: "Funke wallet",
            }));
        }

        gridDiv.appendChild(cell1);
        gridDiv.appendChild(cell2);

        qrContainer.appendChild(fixedGridDiv);
    });
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