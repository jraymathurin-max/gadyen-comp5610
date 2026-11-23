// Shows login/register errors. External file (not inline) so the
// Content-Security-Policy "script-src 'self'" can block injected inline scripts.
(function () {
    const MESSAGES = {
        "1": null, // keep the page's default text
        "locked": "Too many failed attempts. Please wait 15 minutes and try again.",
        "rate": "Too many attempts. Please try again later.",
        "idle": "You were signed out after 10 minutes without activity. Please sign in again.",
        "policy": "Username must be 3-32 letters/digits; password must be 12-72 characters and not contain the username."
    };
    const code = new URLSearchParams(window.location.search).get("error");
    const el = document.querySelector(".error-msg");
    if (!code || !el) return;
    if (Object.prototype.hasOwnProperty.call(MESSAGES, code) && MESSAGES[code]) {
        el.textContent = MESSAGES[code]; // textContent: never interpreted as HTML
    }
    el.style.display = "block";
    window.history.replaceState({}, "", window.location.pathname);
    // The lockout and sign-out notices stay visible; other errors fade after 5 seconds.
    if (code !== "locked" && code !== "idle") {
        setTimeout(() => { el.style.display = "none"; }, 5000);
    }
})();
