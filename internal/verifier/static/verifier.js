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

function hideError(containerId) {
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

//TODO: säkerställ att data även rensas från DOM:en om det är känslig data
function hideElement(id) {
    let el = document.getElementById(id);
    if (el) {
        el.classList.add("is-hidden");
    }
}

function toggleElement(id) {
    let el = document.getElementById(id);
    if (el) {
        el.classList.toggle("is-hidden");
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