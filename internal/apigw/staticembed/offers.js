function hashState() {
    if (!window.location.hash) {
        window.location.hash = "";
    }
    const credRoot = document.querySelector("#cred");

    const updateHashState = (hash) => {
        credRoot.innerHTML = "";
        const el = document.querySelector(hash);
        if (el) {
            credRoot.innerHTML = el.innerHTML;
        }
    };

    if (window.location.hash !== "") {
        updateHashState(window.location.hash);
    }

    window.addEventListener("hashchange", (event) => {
        const { hash } = new URL(event.newURL);

        updateHashState(hash);
    });
}

function navigation() {
    const select = document.querySelector("#credential");

    select?.addEventListener("change", (event) => {
        const { value } = /** @type {HTMLSelectElement} */(event.target)

        if (value) {
            window.location.hash = value;
        }
    });
}

(function main() {
    hashState();
    navigation();
})();