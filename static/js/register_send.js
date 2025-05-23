/**
 * register_send.js - UPROSZCZONA wersja rejestracji
 * Używa prostszego API bez zbędnych komplikacji
 */
document.addEventListener('DOMContentLoaded', function() {
    const registerForm = document.getElementById('registerForm');
    const statusDiv = document.getElementById('status');
    
    if (!registerForm) {
        console.error("❌ Formularz rejestracji nie znaleziony");
        return;
    }
    
    console.log("✅ Register script załadowany");
    
    registerForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        statusDiv.style.display = 'block';
        statusDiv.innerHTML = '🔄 Przetwarzanie rejestracji...';
        
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;

        // UPROSZCZONA walidacja
        if (!username || username.length < 3) {
            showStatus('❌ Nazwa użytkownika musi mieć co najmniej 3 znaki', 'error');
            return;
        }

        if (!password || password.length < 8) {
            showStatus('❌ Hasło musi mieć co najmniej 8 znaków', 'error');
            return;
        }

        // Sprawdź podstawowe wymagania hasła
        if (!/[A-Z]/.test(password)) {
            showStatus('❌ Hasło musi zawierać co najmniej jedną wielką literę', 'error');
            return;
        }

        if (!/\d/.test(password)) {
            showStatus('❌ Hasło musi zawierać co najmniej jedną cyfrę', 'error');
            return;
        }

        if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
            showStatus('❌ Hasło musi zawierać co najmniej jeden znak specjalny', 'error');
            return;
        }

        try {
            statusDiv.innerHTML = '🔑 Generowanie kluczy kryptograficznych...';
            
            // Generowanie pary kluczy RSA
            const keyPair = await generateRSAKeyPair();
            const publicKeyPEM = await exportPublicKeyToPEM(keyPair.publicKey);
            const privateKeyPEM = await exportPrivateKeyToPEM(keyPair.privateKey);

            // Przygotuj klucz prywatny do pobrania
            const privateKeyBlob = new Blob([privateKeyPEM], { type: 'application/x-pem-file' });
            const privateKeyURL = URL.createObjectURL(privateKeyBlob);

            statusDiv.innerHTML = '📤 Wysyłanie danych rejestracji...';

            // Wyślij dane rejestracji
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

            if (response.ok && result.status === 'success') {
                // Sukces rejestracji
                showStatus(`
                    <div style="text-align: center;">
                        <h3>✅ Rejestracja pomyślna!</h3>
                        <p><strong>Twój identyfikator użytkownika: <span style="font-size: 1.2em; color: #FF9800;">${result.user_id}</span></strong></p>
                        <p style="margin: 15px 0;">⚠️ <strong>WAŻNE:</strong> Pobierz klucz prywatny teraz - nie będzie dostępny później!</p>
                        <a href="${privateKeyURL}" download="${username}_private_key.pem" class="download-button" style="display: inline-block; margin: 10px 0; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 4px; font-weight: bold;">
                            📥 Pobierz klucz prywatny
                        </a>
                        <p style="margin-top: 15px;">
                            <a href="/" style="color: #FF9800; text-decoration: none; font-weight: bold;">
                                ➡️ Przejdź do logowania
                            </a>
                        </p>
                    </div>
                `, 'success');
                
                // Automatyczne przekierowanie po 10 sekundach
                setTimeout(() => {
                    window.location.href = '/';
                }, 10000);
                
            } else {
                // Błąd rejestracji
                let errorMessage = 'Wystąpił błąd podczas rejestracji';
                
                switch(result.code) {
                    case 'user_exists':
                        errorMessage = 'Użytkownik o tej nazwie już istnieje';
                        break;
                    case 'password_too_short':
                        errorMessage = 'Hasło jest za krótkie';
                        break;
                    case 'invalid_key_format':
                        errorMessage = 'Błąd generowania klucza kryptograficznego';
                        break;
                    default:
                        errorMessage = result.message || 'Nieznany błąd rejestracji';
                }
                
                showStatus('❌ ' + errorMessage, 'error');
            }
        } catch (error) {
            console.error('❌ Błąd rejestracji:', error);
            showStatus('❌ Wystąpił błąd podczas rejestracji: ' + error.message, 'error');
        }
    });

    /**
     * Wyświetla status z odpowiednim stylem
     */
    function showStatus(message, type = 'info') {
        statusDiv.innerHTML = message;
        statusDiv.className = `status-${type}`;
        
        // Ustaw kolor tła w zależności od typu
        switch(type) {
            case 'success':
                statusDiv.style.backgroundColor = '#d4edda';
                statusDiv.style.color = '#155724';
                statusDiv.style.border = '1px solid #c3e6cb';
                break;
            case 'error':
                statusDiv.style.backgroundColor = '#f8d7da';
                statusDiv.style.color = '#721c24';
                statusDiv.style.border = '1px solid #f5c6cb';
                break;
            default:
                statusDiv.style.backgroundColor = '#d1ecf1';
                statusDiv.style.color = '#0c5460';
                statusDiv.style.border = '1px solid #bee5eb';
        }
        
        statusDiv.style.padding = '15px';
        statusDiv.style.borderRadius = '4px';
        statusDiv.style.marginTop = '15px';
    }

    /**
     * Generuje parę kluczy RSA do podpisywania
     */
    async function generateRSAKeyPair() {
        try {
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
        } catch (error) {
            console.error('❌ Błąd generowania kluczy:', error);
            throw new Error('Nie można wygenerować kluczy kryptograficznych');
        }
    }

    /**
     * Eksportuje klucz publiczny do formatu PEM
     */
    async function exportPublicKeyToPEM(publicKey) {
        try {
            const spki = await window.crypto.subtle.exportKey("spki", publicKey);
            const base64 = arrayBufferToBase64(spki);
            return `-----BEGIN PUBLIC KEY-----\n${formatBase64(base64)}\n-----END PUBLIC KEY-----`;
        } catch (error) {
            console.error('❌ Błąd eksportu klucza publicznego:', error);
            throw new Error('Nie można wyeksportować klucza publicznego');
        }
    }

    /**
     * Eksportuje klucz prywatny do formatu PEM
     */
    async function exportPrivateKeyToPEM(privateKey) {
        try {
            const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", privateKey);
            const base64 = arrayBufferToBase64(pkcs8);
            return `-----BEGIN PRIVATE KEY-----\n${formatBase64(base64)}\n-----END PRIVATE KEY-----`;
        } catch (error) {
            console.error('❌ Błąd eksportu klucza prywatnego:', error);
            throw new Error('Nie można wyeksportować klucza prywatnego');
        }
    }

    /**
     * Konwertuje ArrayBuffer na Base64
     */
    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Formatuje Base64 z podziałami co 64 znaki (format PEM)
     */
    function formatBase64(base64) {
        let formatted = '';
        for (let i = 0; i < base64.length; i += 64) {
            formatted += base64.slice(i, i + 64) + '\n';
        }
        return formatted.trim();
    }
    
    console.log("✅ Register script gotowy");
});
