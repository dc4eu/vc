const baseUrl = window.location.origin;

const getElementById = (id) => document.getElementById(id);

const removeElementById = (id) => {
    getElementById(id)?.remove();
};

function showError(containerId, message) {
    const errorElement = document.getElementById(containerId);
    if (errorElement) {
        errorElement.textContent = message;
        errorElement.classList.remove("is-hidden");
    }
}

function clearAndHideError(containerId) {
    const errorElement = document.getElementById(containerId);
    if (errorElement) {
        errorElement.textContent = "";
        errorElement.classList.add("is-hidden");
    }
}

function showElement(id) {
    let el = document.getElementById(id);
    if (el) {
        el.classList.remove("is-hidden");
    }
}

function showElements(elementIds) {
    elementIds.forEach(id => document.getElementById(id)?.classList.remove("is-hidden"));
}

function hideElement(id) {
    let el = document.getElementById(id);
    if (el) {
        el.classList.add("is-hidden");
    }
}

function showIcon(id) {
    hideIcons();
    let el = document.getElementById(id);
    if (el) {
        el.classList.remove("is-hidden");
    }
}

function hideIcons() {
    let icons = ["spinnerIcon", "okIcon", "errorIcon"];
    icons.forEach(id => {
        let el = document.getElementById(id);
        if (el) {
            el.classList.add("is-hidden");
        }
    });
}

function resetAndHideIndexContainer() {
    hideElement("indexContainer");
}

function resetAndHideQRContainer() {
    clearAndHideError("qrErrorMessage");
    //TODO rensa ev. data inom containern (qr och knapp-data) samt återställ knappar som dolda igen
    hideElement("qrContainer");
}

function resetAndHideVerificationContainer() {
    clearAndHideError("verificationErrorMessage");
    showIcon("spinnerIcon");
    //TODO rensa ev. data inom containern (claims)
    hideElement("verificationContainer");
}

async function startVPFlow() {
    console.log("startVPFlow");
    const documentTypeElement = getElementById("documentTypeSelect");
    console.log("documentTypeElement", documentTypeElement.value);

    resetAndHideIndexContainer();
    showElement("qrContainer");

    try {
        const response = await fetch(new URL("/qrcode", baseUrl), {
            method: "POST",
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json; charset=utf-8',
            },
            body: JSON.stringify({document_type: documentTypeElement.value})
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();

        if (!data.base64_image || !data.uri || !data.request_uri || !data.client_id) {
            throw new Error("Invalid response data");
        }

        displayQRCode({
            base64_image: data.base64_image,
            uri: data.uri,
            request_uri: data.request_uri,
            client_id: data.client_id,
        });
    } catch (error) {
        console.error("Error fetching QR code:", error);
        qrErrorMessage = `An error occurred: ${error.message}`;
        showError("qrErrorMessage", qrErrorMessage);
    }

    function displayQRCode(data) {
        const qrImage = document.getElementById("qrImage");
        qrImage.src = `data:image/png;base64,${data.base64_image}`;
        qrImage.title = data.uri;
        qrImage.classList.remove("is-hidden");

        const openInDemoWWWalletButton = document.getElementById("openInDemoWWWalletButton");
        //example: https://demo.wwwallet.org/cb?client_id=verifier.wwwallet.org&request_uri=https%3A%2F%2Fverifier.wwwallet.org%2Fverification%2Frequest-object%3Fid%3D2f96a24e-90cc-4b30-a904-912e9980df10
        const demoWWWalletBaseUrl = "https://demo.wwwallet.org/cb";
        const params = new URLSearchParams({
            client_id: data.client_id,
            request_uri: encodeURIComponent(data.request_uri)
        });
        const demoWWWalletURL =  `${demoWWWalletBaseUrl}?${params.toString()}`;
        openInDemoWWWalletButton.onclick = () => window.open(demoWWWalletURL, "_blank");
        openInDemoWWWalletButton.title = demoWWWalletURL;
        openInDemoWWWalletButton.classList.remove("is-hidden");

        const checkVerificationResultButton = document.getElementById("checkVerificationResultButton");
        checkVerificationResultButton.onclick = () => checkVPVerification();
        checkVerificationResultButton.classList.remove("is-hidden");

        const qrInfoText = document.getElementById("qrInfoText");
        qrInfoText.classList.remove("is-hidden");
    }
}


function checkVPVerification() {
    console.log("checkVPVerification");
    resetAndHideQRContainer();
    showElement("verificationContainer");
}

function resetVPFlow() {
    console.log("resetVPFlow");

    resetAndHideQRContainer();
    resetAndHideVerificationContainer();
    showElement("indexContainer");

    //TODO: ta bort sessionen (cookie) + begär även på serversidan
}



