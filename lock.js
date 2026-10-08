/**
 * lock.js
 * In-browser AES-GCM (256-bit) decryption for password-locked blog posts.
 * Uses native Web Crypto API (supported in all modern browsers).
 */

async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );
}

function base64ToBuf(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
}

async function unlockPost() {
    const input = document.getElementById("post-passcode");
    const errorEl = document.getElementById("lock-error");
    const lockBox = document.getElementById("lock-box");
    const contentBox = document.getElementById("decrypted-content");

    if (!input) return;
    const password = input.value.trim();
    if (!password) {
        errorEl.textContent = "Please enter an access code.";
        errorEl.style.display = "block";
        return;
    }

    try {
        errorEl.style.display = "none";
        const cipherPayload = window.LOCKED_POST;
        if (!cipherPayload) {
            errorEl.textContent = "Error: Encrypted content not found.";
            errorEl.style.display = "block";
            return;
        }

        const salt = base64ToBuf(cipherPayload.salt);
        const iv = base64ToBuf(cipherPayload.iv);
        const ciphertext = base64ToBuf(cipherPayload.data);

        const key = await deriveKey(password, salt);
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            ciphertext
        );

        const dec = new TextDecoder();
        const html = dec.decode(decrypted);

        // Display decrypted content and hide lock UI
        contentBox.innerHTML = html;
        contentBox.style.display = "block";
        lockBox.style.display = "none";

        // Save pass in session storage so refresh doesn't relock during same tab session
        sessionStorage.setItem("post_unlocked_" + window.location.pathname, password);
    } catch (e) {
        errorEl.textContent = "Incorrect access code. Permission denied.";
        errorEl.style.display = "block";
        input.value = "";
        input.focus();
    }
}

// Check session on load
window.addEventListener("DOMContentLoaded", () => {
    const saved = sessionStorage.getItem("post_unlocked_" + window.location.pathname);
    if (saved) {
        const input = document.getElementById("post-passcode");
        if (input) {
            input.value = saved;
            unlockPost();
        }
    }
});
