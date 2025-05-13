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
    const documentTypeSelect = document.getElementById("documentTypeSelect");
    const defaultOption = Array.from(documentTypeSelect.options).find(opt => opt.defaultSelected);
    if (defaultOption) {
        documentTypeSelect.value = defaultOption.value;
    }

    hideElement("indexContainer");
}

function resetAndHideQRContainer() {
    clearAndHideError("qrErrorMessage");

    const qrImage = getElementById("qrImage");
    qrImage.src = "";
    qrImage.title = "";
    qrImage.classList.add("is-hidden");

    const qrInfoText = getElementById("qrInfoText");
    qrInfoText.classList.add("is-hidden");

    const openInDemoWWWalletButton = getElementById("openInDemoWWWalletButton");
    openInDemoWWWalletButton.title = "";
    openInDemoWWWalletButton.onclick = null;
    openInDemoWWWalletButton.classList.add("is-hidden");

    const openInDC4EUWWWalletButton = getElementById("openInDC4EUWWWalletButton");
    openInDC4EUWWWalletButton.title = "";
    openInDC4EUWWWalletButton.onclick = null;
    openInDC4EUWWWalletButton.classList.add("is-hidden");

    const checkVerificationResultButton = getElementById("checkVerificationResultButton");
    checkVerificationResultButton.title = "";
    checkVerificationResultButton.onclick = null;
    checkVerificationResultButton.classList.add("is-hidden");

    hideElement("qrContainer");
}

function resetAndHideVerificationContainer() {
    resetVerificationContainer();
    hideElement("verificationContainer");
}

function resetVerificationContainer() {
    clearAndHideError("verificationErrorMessage");
    showIcon("spinnerIcon");
    getElementById("interactionStatusValue").textContent = "Unknown";
    getElementById("claimsDisplay").value = "";
}

async function startVPFlow() {
    const documentTypeValue = getElementById("documentTypeSelect").value;

    resetAndHideIndexContainer();
    resetAndHideQRContainer();
    showElement("qrContainer");

    try {
        const response = await fetch(new URL("/qr-code", baseUrl), {
            method: "POST",
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json; charset=utf-8',
            },
            body: JSON.stringify({document_type: documentTypeValue})
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
        const qrErrorMessage = `An error occurred: ${error.message}`;
        showError("qrErrorMessage", qrErrorMessage);
    }

    function displayQRCode(data) {
        const qrImage = document.getElementById("qrImage");
        qrImage.src = `data:image/png;base64,${data.base64_image}`;
        qrImage.title = data.uri;
        qrImage.classList.remove("is-hidden");

        const qrInfoText = document.getElementById("qrInfoText");
        qrInfoText.classList.remove("is-hidden");

        //example: https://demo.wwwallet.org/cb?client_id=verifier.wwwallet.org&request_uri=https%3A%2F%2Fverifier.wwwallet.org%2Fverification%2Frequest-object%3Fid%3D2f96a24e-90cc-4b30-a904-912e9980df10
        const params = new URLSearchParams({
            client_id: data.client_id,
            //request_uri: encodeURIComponent(data.request_uri)
            request_uri: data.request_uri
        });

        const openInDC4EUWWWalletButton = document.getElementById("openInDC4EUWWWalletButton");
        const dc4euWWWalletURL = `https://dc4eu.wwwallet.org/cb?${params.toString()}`;
        openInDC4EUWWWalletButton.onclick = () => window.open(dc4euWWWalletURL, "_blank");
        openInDC4EUWWWalletButton.title = dc4euWWWalletURL;
        openInDC4EUWWWalletButton.classList.remove("is-hidden");

        const openInDemoWWWalletButton = document.getElementById("openInDemoWWWalletButton");
        const demoWWWalletURL = `https://demo.wwwallet.org/cb?${params.toString()}`;
        openInDemoWWWalletButton.onclick = () => window.open(demoWWWalletURL, "_blank");
        openInDemoWWWalletButton.title = demoWWWalletURL;
        openInDemoWWWalletButton.classList.remove("is-hidden");

        const checkVerificationResultButton = document.getElementById("checkVerificationResultButton");
        checkVerificationResultButton.onclick = () => checkVPVerificationResult();
        checkVerificationResultButton.classList.remove("is-hidden");
    }
}


function checkVPVerificationResult() {
    console.log("checkVPVerification");
    resetAndHideQRContainer();
    resetAndHideVerificationContainer();
    showElement("verificationContainer");
    refreshVerificationResult();
}

async function refreshVerificationResult() {
    resetVerificationContainer();
    try {
        const response = await fetch(new URL("/verificationresult", baseUrl), {
            method: "GET",
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json; charset=utf-8',
            },
        });

        if (!response.ok) {
            let errorBody = '';
            try {
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    const json = await response.json();
                    errorBody = JSON.stringify(json, null, 2);
                } else {
                    errorBody = await response.text();
                }
            } catch (e) {
                errorBody = 'Kunde inte läsa felmeddelande från svaret.';
            }
            throw new Error(`HTTP error! Status ${response.status} ${response.statusText}\n\nBody:\n${errorBody}`);
        }

        const data = await response.json();
        console.log("Verification Result: interaction_status=" + data.interaction_status + " with data=" + data.data);

        getElementById("interactionStatusValue").textContent = data.interaction_status;

        const claimsDisplay = getElementById("claimsDisplay");
        if (data && data.data && Object.keys(data.data).length > 0) {
            claimsDisplay.value = JSON.stringify(data.data, null, 2);
        } else {
            claimsDisplay.value = '';
        }
    } catch (error) {
        console.error("Error fetching and displaying verification result:", error);
        const verificationResultErrorMessage = `An error occurred: ${error.message}`;
        showError("verificationErrorMessage", verificationResultErrorMessage);
    }
}

async function quitVPFlow() {
    console.log("resetVPFlow");

    resetAndHideQRContainer();
    resetAndHideVerificationContainer();
    showElement("indexContainer");

    try {
        const response = await fetch(new URL("/quitvpflow", baseUrl), {
            method: "DELETE",
            //credentials: "include", //If frontend and backend have different origin or subdomains
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json; charset=utf-8',
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
    } catch (error) {
        console.error("Error during quitvpflow:", error);
        //TODO: ska man och i så fall var ska man visa detta i GUI't?
    }
}

document.addEventListener('DOMContentLoaded', function () {
    const startVPFlowButton = document.getElementById('start-vp-flow-btn');
    startVPFlowButton.addEventListener('click', function () {
        startVPFlow();
    });

    const documentTypeSelect = document.getElementById('documentTypeSelect');
    documentTypeSelect.addEventListener('keydown', function (event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            startVPFlowButton.click();
        }
    });
});


