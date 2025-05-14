document.addEventListener('DOMContentLoaded', function () {
    const isLoginPage = window.location.pathname === '/' || window.location.pathname === '/login';

    if (!isLoginPage && window.sessionManager && !window.sessionManager.isLoggedIn) {
        window.location.href = '/?next=' + encodeURIComponent(window.location.pathname);
        return;
    }

    const loginForm = document.getElementById("login-form");
    
    if (loginForm) {
        loginForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            event.stopPropagation();
            await handleLogin();
        });
        
        const loginButton = document.getElementById("login-button");
        if (loginButton) {
            loginButton.addEventListener("click", async function() {
                await handleLogin();
            });
        }
    }
    
    // Funkcja obsługi logowania
    async function handleLogin() {
        const username = document.getElementById("username").value.trim();
        const password = document.getElementById("password").value;
        const pemFileInput = document.getElementById("pem-file");
        let statusDiv = document.getElementById("login-status");

        if (!statusDiv) {
            const newStatusDiv = document.createElement("div");
            newStatusDiv.id = "login-status";
            newStatusDiv.style.display = "block";
            loginForm.appendChild(newStatusDiv);
            statusDiv = newStatusDiv;
        } else {
            statusDiv.style.display = "block";
        }

        statusDiv.textContent = "Logowanie...";

        if (!pemFileInput || !pemFileInput.files || !pemFileInput.files[0]) {
            statusDiv.textContent = "Wybierz plik klucza prywatnego (.pem)";
            return;
        }

        try {
            const file = pemFileInput.files[0];
            const privateKeyPEM = await file.text();
            
            const privateKey = await importPrivateKeyFromPEM(privateKeyPEM);
            
            const encoder = new TextEncoder();
            const passwordData = encoder.encode(password);

            const signature = await window.crypto.subtle.sign(
                {
                    name: "RSASSA-PKCS1-v1_5"
                },
                privateKey,
                passwordData
            );

            const signatureBase64 = arrayBufferToBase64(signature);

            const jsonData = {
                username: username,
                password: password,
                signature: signatureBase64
            };

            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(jsonData),
                credentials: 'same-origin'
            });

            if (!response.ok) {
                statusDiv.textContent = `Błąd serwera: ${response.status} ${response.statusText}`;
                return;
            }

            const result = await response.json();

            if (result.status === 'success') {
                const message = getMessage(result.code) || 'Zalogowano pomyślnie!';
                statusDiv.innerHTML = `${message} Twój identyfikator: <strong>${result.user_id}</strong><br>Za chwilę nastąpi przekierowanie...`;
                // KLUCZOWA ZMIANA: Bezpośrednie przekierowanie do /chat bez sprawdzania warunków
                setTimeout(() => {
                    window.location.href = '/chat';
                }, 1500);
}

                // Jeśli istnieje sessionManager, zaktualizuj jego stan
                if (window.sessionManager) {
                    window.sessionManager.login({
                        user_id: result.user_id,
                        username: username,
                        is_admin: isAdmin
                    });
                }

                // Sprawdź, czy istnieje parametr next w URL
                const urlParams = new URLSearchParams(window.location.search);
                const nextUrl = urlParams.get('next');
                
                // Przekierowanie po krótkim opóźnieniu
                setTimeout(() => {
                    if (nextUrl) {
                        window.location.href = nextUrl;
                    } else if (isAdmin) {
                        window.location.href = '/admin_dashboard';
                    } else {
                        window.location.href = '/chat';
                    }
                }, 1500);
            } else {
                statusDiv.textContent = getMessage(result.code) || result.error || 'Błąd logowania';
            }
        } catch (error) {
            statusDiv.textContent = "Błąd logowania lub podpisu. Sprawdź plik PEM.";
        }
    }

    async function importPrivateKeyFromPEM(pem) {
        if (!pem.includes("-----BEGIN PRIVATE KEY-----")) {
            throw new Error("Nieprawidłowy format klucza prywatnego");
        }

        const pemContents = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace(/\s+/g, "");

        const binaryDer = str2ab(atob(pemContents));

        return await window.crypto.subtle.importKey(
            "pkcs8",
            binaryDer,
            {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256"
            },
            false,
            ["sign"]
        );
    }

    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    function str2ab(str) {
        const buf = new ArrayBuffer(str.length);
        const bufView = new Uint8Array(buf);
        for (let i = 0; i < str.length; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return buf;
    }

    function getMessage(code) {
        switch (code) {
            case 'login_ok':
                return "Zalogowano pomyślnie!";
            case 'invalid_credentials':
                return "Niepoprawna nazwa użytkownika lub hasło.";
            case 'invalid_password':
                return "Niepoprawne hasło.";
            case 'invalid_signature':
                return "Niepoprawny podpis cyfrowy. Upewnij się, że używasz właściwego klucza prywatnego.";
            case 'missing_data':
                return "Brakuje wymaganych danych.";
            default:
                return null;
        }
    }
});