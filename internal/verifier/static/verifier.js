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
    let icons = ["unknownIcon", "scanQRIcon", "spinnerIcon", "okIcon", "errorIcon", "rejectedIcon"];
    icons.forEach(id => {
        let el = document.getElementById(id);
        if (el) {
            el.classList.add("is-hidden");
        }
    });
}

function resetAndHideIndexContainer() {
    const presentationRequestTypeIDSelect = document.getElementById("presentationRequestTypeIDSelect");
    const defaultOption1 = Array.from(presentationRequestTypeIDSelect.options).find(opt => opt.defaultSelected);
    if (defaultOption1) {
        presentationRequestTypeIDSelect.value = defaultOption1.value;
    }

    const documentTypeSelect = document.getElementById("documentTypeSelect");
    const defaultOption2 = Array.from(documentTypeSelect.options).find(opt => opt.defaultSelected);
    if (defaultOption2) {
        documentTypeSelect.value = defaultOption2.value;
    }

    getElementById("encryptWalletResponseCB").checked = getElementById("encryptWalletResponseCB").defaultChecked;

    hideElement("indexContainer");
}

function resetButton(buttonId) {
    const button = document.getElementById(buttonId);
    if (!button) return;
    button.title = "";
    button.onclick = null;
    button.classList.add("is-hidden");
}


function resetAndHideQRContainer() {
    clearAndHideError("qrErrorMessage");

    const qrImage = getElementById("qrImage");
    qrImage.src = "";
    qrImage.title = "";
    qrImage.classList.add("is-hidden");

    const qrInfoText = getElementById("qrInfoText");
    qrInfoText.classList.add("is-hidden");

    resetButton("openInDemoWWWalletButton");
    resetButton("openInDC4EUWWWalletButton");
    resetButton("openInDevSUNETWalletButton");
    resetButton("openInFunkeWalletButton");
    resetButton("checkVerificationResultButton");

    hideElement("qrContainer");
}

function resetAndHideVerificationContainer() {
    resetVerificationContainer();
    hideElement("verificationContainer");
}

function resetVerificationContainer() {
    clearAndHideError("verificationErrorMessage");
    showIcon("unknownIcon");
    getElementById("interactionStatusSpan").textContent = "unknown";
    getElementById("verificationResultSpan").textContent = "unknown";
    getElementById("vpSessionIDSpan").textContent = "unknown";
    getElementById("claimsDisplay").value = "";
}

async function startVPFlow() {
    const documentTypeValue = getElementById("documentTypeSelect").value;
    const presentationRequestTypeValue = getElementById("presentationRequestTypeIDSelect").value;
    const encryptWalletResponse = getElementById("encryptWalletResponseCB").checked;

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
            body: JSON.stringify({
                presentation_request_type_id: presentationRequestTypeValue,
                document_type: documentTypeValue,
                encrypt_direct_post_jwt: encryptWalletResponse,
            })
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

        const openInDevSUNETWalletButton = document.getElementById("openInDevSUNETWalletButton");
        const devSUNETWalletURL = `https://dev.wallet.sunet.se/cb?${params.toString()}`;
        openInDevSUNETWalletButton.onclick = () => window.open(devSUNETWalletURL, "_blank");
        openInDevSUNETWalletButton.title = devSUNETWalletURL;
        openInDevSUNETWalletButton.classList.remove("is-hidden");

        const openInFunkeWalletButton = document.getElementById("openInFunkeWalletButton");
        const funkeWalletURL = `https://funke.wwwallet.org/cb?${params.toString()}`;
        openInFunkeWalletButton.onclick = () => window.open(funkeWalletURL, "_blank");
        openInFunkeWalletButton.title = funkeWalletURL;
        openInFunkeWalletButton.classList.remove("is-hidden");

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
        const interactionStatus = data.interaction_status;
        console.debug("interaction_status=" + interactionStatus + " with data=" + data.data);

        getElementById("interactionStatusSpan").textContent = interactionStatus;
        if (interactionStatus === "qr_displayed") {
            showIcon("scanQRIcon");
        } else {
            showIcon("spinnerIcon");
        }
        getElementById("vpSessionIDSpan").textContent = data.vp_session_id;

        const claimsDisplay = getElementById("claimsDisplay");
        if (data && data.data && Object.keys(data.data).length > 0) {
            // the verifier has received some response from the wallet
            const verificationResultValue = data?.data?.verification_meta?.verification_result || null;
            if (verificationResultValue !== null) {
                getElementById("verificationResultSpan").textContent = verificationResultValue;
                if (verificationResultValue === "verified") {
                    showIcon("okIcon");
                } else if (verificationResultValue === "rejected") {
                    showIcon("rejectedIcon");
                } else if (verificationResultValue === "error") {
                    showIcon("errorIcon");
                }
            }
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
    
    const presentationRequestTypeIDSelect = document.getElementById('presentationRequestTypeIDSelect');
    presentationRequestTypeIDSelect.addEventListener('keydown', function (event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            startVPFlowButton.click();
        }
    });

    const documentTypeSelect = document.getElementById('documentTypeSelect');
    documentTypeSelect.addEventListener('keydown', function (event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            startVPFlowButton.click();
        }
    });

    const encryptWalletResponseCB = document.getElementById('encryptWalletResponseCB');
    encryptWalletResponseCB.addEventListener('keydown', function (event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            startVPFlowButton.click();
        }
    });
});


