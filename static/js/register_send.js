document.addEventListener('DOMContentLoaded', function() {
    const registerForm = document.getElementById('registerForm');
    const statusDiv = document.getElementById('status');
    
    if (!registerForm) {
        return;
    }
    
    registerForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        statusDiv.style.display = 'block';
        statusDiv.innerText = 'Przetwarzanie...';
        
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;

        // Walidacja użytkownika
        if (username.length < 3 || /\s/.test(username)) {
            statusDiv.innerText = 'Login musi mieć min. 3 znaki i nie może zawierać spacji.';
            return;
        }

        const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$/;
        if (!passwordRegex.test(password)) {
            statusDiv.innerText = 'Hasło musi mieć min. 8 znaków, dużą literę, cyfrę i znak specjalny.';
            return;
        }

        try {
            // Generowanie pary kluczy RSA po stronie klienta
            const keyPair = await generateRSAKeyPair();
            const publicKeyPEM = await exportPublicKeyToPEM(keyPair.publicKey);
            const privateKeyPEM = await exportPrivateKeyToPEM(keyPair.privateKey);

            // Zapisz klucz prywatny do pobrania
            const privateKeyBlob = new Blob([privateKeyPEM], { type: 'application/x-pem-file' });
            const privateKeyURL = URL.createObjectURL(privateKeyBlob);

            // Wysłanie danych do API z kluczem publicznym
            const response = await fetch("/api/register", {
                method: "POST",
                headers: { 
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ 
                    username: username, 
                    password: password,
                    public_key: publicKeyPEM 
                })
            });
            
            const result = await response.json();

            if (response.ok) {
                try {
                    const message = getMessage(result.code) || 'Zarejestrowano pomyślnie!';
                    
                    statusDiv.innerHTML = `
                        <p>${message}</p>
                        <p><strong>Twój identyfikator użytkownika: ${result.user_id}</strong></p>
                        <p>Zapisz ten identyfikator, będzie Ci potrzebny do identyfikacji.</p>
                        <p>Twój klucz prywatny jest gotowy do pobrania. Musisz go pobrać teraz, ponieważ <strong>NIE</strong> jest przechowywany na serwerze i nie będzie dostępny później!</p>
                        <p><a href="${privateKeyURL}" download="${username}_private_key.pem" class="download-button">Pobierz klucz prywatny</a></p>
                        <p>Zachowaj ten klucz w bezpiecznym miejscu. Będzie wymagany do logowania.</p>
                    `;
                } catch (err) {
                    statusDiv.innerHTML = `
                        <p>Zarejestrowano pomyślnie!</p>
                        <p><strong>Twój identyfikator użytkownika: ${result.user_id}</strong></p>
                        <p><a href="${privateKeyURL}" download="${username}_private_key.pem" class="download-button">Pobierz klucz prywatny</a></p>
                    `;
                }
            } else {
                try {
                    statusDiv.innerText = getMessage(result.code) || result.error || 'Błąd rejestracji';
                } catch (err) {
                    statusDiv.innerText = result.error || 'Błąd rejestracji';
                }
            }
        } catch (error) {
            statusDiv.innerText = 'Wystąpił błąd podczas rejestracji lub generowania kluczy.';
        }
    });

    // Funkcja generująca parę kluczy RSA
    async function generateRSAKeyPair() {
        return await window.crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]), // 65537
                hash: { name: "SHA-256" }
            },
            true, // Możliwość eksportu kluczy
            ["sign", "verify"] // Operacje dozwolone dla kluczy
        );
    }

    // Funkcja eksportująca klucz publiczny do formatu PEM
    async function exportPublicKeyToPEM(publicKey) {
        // Eksport klucza do formatu SPKI
        const spki = await window.crypto.subtle.exportKey("spki", publicKey);
        
        // Konwersja na Base64
        const base64 = arrayBufferToBase64(spki);
        
        // Format PEM
        return `-----BEGIN PUBLIC KEY-----\n${base64}\n-----END PUBLIC KEY-----`;
    }

    // Funkcja eksportująca klucz prywatny do formatu PEM
    async function exportPrivateKeyToPEM(privateKey) {
        // Eksport klucza do formatu PKCS8
        const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", privateKey);
        
        // Konwersja na Base64
        const base64 = arrayBufferToBase64(pkcs8);
        
        // Format PEM
        return `-----BEGIN PRIVATE KEY-----\n${base64}\n-----END PRIVATE KEY-----`;
    }

    // Funkcja pomocnicza do konwersji ArrayBuffer na Base64
    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        const base64 = btoa(binary);
        
        // Dodajemy podziały co 64 znaki zgodnie z formatem PEM
        let formattedBase64 = '';
        for (let i = 0; i < base64.length; i += 64) {
            formattedBase64 += base64.slice(i, i + 64) + '\n';
        }
        return formattedBase64.trim();
    }
});