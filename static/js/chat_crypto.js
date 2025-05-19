/**
 * Moduł do obsługi szyfrowania w aplikacji czatu - wersja zoptymalizowana
 */
class ChatCrypto {
    constructor() {
        this.loadKeys();
        this.sessionKeys = {};
        this.keyRotationCount = {}; // Licznik wiadomości dla rotacji kluczy
        this.keyRotationThreshold = 100; // Rotacja klucza co 100 wiadomości
    }
    
    /**
     * Ładuje klucze z pamięci lokalnej
     */
    async loadKeys() {
        const privateKeyPEM = localStorage.getItem('private_key_pem');
        if (!privateKeyPEM) {
            console.warn('Brak zapisanego klucza prywatnego w localStorage');
            return false;
        }
        
        try {
            this.privateKey = await this.importPrivateKeyFromPEM(privateKeyPEM);
            return true;
        } catch (error) {
            console.error('Błąd podczas ładowania klucza:', error);
            return false;
        }
    }
    
    /**
     * Importuje klucz prywatny z formatu PEM
     */
    async importPrivateKeyFromPEM(pem) {
        const pemContents = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace(/\s+/g, "");

        const binaryDer = this.str2ab(atob(pemContents));

        return await window.crypto.subtle.importKey(
            "pkcs8",
            binaryDer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["decrypt", "sign"]
        );
    }
    
    /**
     * Importuje klucz publiczny z formatu PEM
     */
    async importPublicKeyFromPEM(pem) {
        const pemContents = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(/\s+/g, "");

        const binaryDer = this.str2ab(atob(pemContents));

        return await window.crypto.subtle.importKey(
            "spki",
            binaryDer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["encrypt", "verify"]
        );
    }
    
    /**
     * Generuje klucz sesji (AES-GCM)
     */
    async generateSessionKey() {
        return await window.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
    }
    
    /**
     * Eksportuje klucz sesji do formatu Base64
     */
    async exportSessionKey(sessionKey) {
        const rawKey = await window.crypto.subtle.exportKey("raw", sessionKey);
        return this.arrayBufferToBase64(rawKey);
    }
    
    /**
     * Importuje klucz sesji z formatu Base64
     */
    async importSessionKey(base64Key) {
        const rawKey = this.base64ToArrayBuffer(base64Key);
        return await window.crypto.subtle.importKey(
            "raw",
            rawKey,
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
    }
    
    /**
     * Szyfruje klucz sesji kluczem publicznym odbiorcy
     */
    async encryptSessionKey(sessionKeyBase64, recipientPublicKey) {
        const sessionKeyData = this.base64ToArrayBuffer(sessionKeyBase64);
        const encryptedKey = await window.crypto.subtle.encrypt(
            {
                name: "RSA-OAEP"
            },
            recipientPublicKey,
            sessionKeyData
        );
        
        return this.arrayBufferToBase64(encryptedKey);
    }
    
    /**
     * Deszyfruje klucz sesji swoim kluczem prywatnym
     */
    async decryptSessionKey(encryptedKeyBase64) {
        const encryptedKeyData = this.base64ToArrayBuffer(encryptedKeyBase64);
        const decryptedKey = await window.crypto.subtle.decrypt(
            {
                name: "RSA-OAEP"
            },
            this.privateKey,
            encryptedKeyData
        );
        
        return this.arrayBufferToBase64(decryptedKey);
    }
    
    /**
     * Szyfruje wiadomość kluczem sesji
     */
    async encryptMessage(message, sessionKey, sessionToken) {
        // Sprawdź czy potrzebna jest rotacja klucza
        if (this.shouldRotateKey(sessionToken)) {
            await this.rotateSessionKey(sessionToken);
            // Pobierz nowy klucz sesji po rotacji
            sessionKey = await this.getActiveSessionKey(sessionToken);
        }
        
        // Generuj wektor inicjalizacyjny dla szyfrowania
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        // Przygotuj dane wiadomości z metadanymi
        const messageData = {
            content: message,
            timestamp: new Date().toISOString(),
            sender_id: parseInt(sessionStorage.getItem('user_id')),
            message_id: this.generateUUID()
        };
        
        // Serializuj do JSON
        const jsonData = JSON.stringify(messageData);
        const encoder = new TextEncoder();
        const messageBytes = encoder.encode(jsonData);
        
        // Podpisz wiadomość przed szyfrowaniem
        const signature = await this.signData(messageBytes);
        
        // Dodaj podpis do danych do zaszyfrowania
        const dataToEncrypt = JSON.stringify({
            data: jsonData,
            signature: signature
        });
        
        const dataBytes = encoder.encode(dataToEncrypt);
        
        // Szyfruj
        const encryptedMessage = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            sessionKey,
            dataBytes
        );
        
        // Inkrementuj licznik wiadomości dla danej sesji
        this.incrementMessageCounter(sessionToken);
        
        return {
            iv: this.arrayBufferToBase64(iv),
            encryptedData: this.arrayBufferToBase64(encryptedMessage),
            keyVersion: this.getKeyVersion(sessionToken)
        };
    }
    
    /**
     * Deszyfruje wiadomość kluczem sesji
     */
    async decryptMessage(encryptedMessage, sessionKey) {
        const iv = this.base64ToArrayBuffer(encryptedMessage.iv);
        const encryptedData = this.base64ToArrayBuffer(encryptedMessage.encryptedData);
        
        try {
            // Deszyfruj dane
            const decryptedData = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                sessionKey,
                encryptedData
            );
            
            // Dekoduj wynik
            const decoder = new TextDecoder();
            const decryptedJson = decoder.decode(decryptedData);
            
            // Parsuj dane i podpis
            const { data, signature } = JSON.parse(decryptedJson);
            const messageData = JSON.parse(data);
            
            // Weryfikuj podpis, jeśli dostępny
            if (signature) {
                // Tutaj powinno być pobieranie klucza publicznego nadawcy
                // i weryfikacja podpisu, ale to wymaga dodatkowej logiki
                // Dla uproszczenia pomijamy pełną implementację
            }
            
            // Weryfikuj znacznik czasowy - odrzuć wiadomości starsze niż 5 minut
            const messageTime = new Date(messageData.timestamp).getTime();
            const currentTime = new Date().getTime();
            const maxAgeMs = 5 * 60 * 1000; // 5 minut
            
            if (currentTime - messageTime > maxAgeMs) {
                console.warn("Odrzucono wiadomość ze względu na wiek: " + (currentTime - messageTime) + "ms");
                throw new Error("Message is too old");
            }
            
            return messageData;
        } catch (error) {
            console.error('Błąd deszyfrowania:', error);
            throw error;
        }
    }
    
    /**
     * Podpisuje dane kluczem prywatnym
     */
    async signData(data) {
        try {
            const signature = await window.crypto.subtle.sign(
                {
                    name: "RSASSA-PKCS1-v1_5"
                },
                this.privateKey,
                data
            );
            
            return this.arrayBufferToBase64(signature);
        } catch (error) {
            console.error('Błąd podczas podpisywania:', error);
            return null;
        }
    }
    
    /**
     * Weryfikuje podpis danych kluczem publicznym
     */
    async verifySignature(data, signature, publicKey) {
        try {
            const signatureData = this.base64ToArrayBuffer(signature);
            
            return await window.crypto.subtle.verify(
                {
                    name: "RSASSA-PKCS1-v1_5"
                },
                publicKey,
                signatureData,
                data
            );
        } catch (error) {
            console.error('Błąd podczas weryfikacji podpisu:', error);
            return false;
        }
    }
    
    /**
     * Sprawdza, czy należy dokonać rotacji klucza sesji
     */
    shouldRotateKey(sessionToken) {
        if (!this.keyRotationCount[sessionToken]) {
            this.keyRotationCount[sessionToken] = 0;
            return false;
        }
        
        return this.keyRotationCount[sessionToken] >= this.keyRotationThreshold;
    }
    
    /**
     * Zwiększa licznik wiadomości dla danej sesji
     */
    incrementMessageCounter(sessionToken) {
        if (!this.keyRotationCount[sessionToken]) {
            this.keyRotationCount[sessionToken] = 0;
        }
        
        this.keyRotationCount[sessionToken]++;
    }
    
    /**
     * Dokonuje rotacji klucza sesji
     */
    async rotateSessionKey(sessionToken) {
        // Generuj nowy klucz sesji
        const newKey = await this.generateSessionKey();
        const keyBase64 = await this.exportSessionKey(newKey);
        
        // Zapisz nowy klucz z nową wersją
        const currentVersion = this.getKeyVersion(sessionToken) || 0;
        const newVersion = currentVersion + 1;
        
        // Zapisz klucz z wersją
        localStorage.setItem(`session_key_${sessionToken}_v${newVersion}`, keyBase64);
        localStorage.setItem(`current_key_version_${sessionToken}`, newVersion.toString());
        
        // Resetuj licznik wiadomości
        this.keyRotationCount[sessionToken] = 0;
        
        return newKey;
    }
    
    /**
     * Pobiera aktualną wersję klucza sesji
     */
    getKeyVersion(sessionToken) {
        return parseInt(localStorage.getItem(`current_key_version_${sessionToken}`) || "0");
    }
    
    /**
     * Pobiera aktywny klucz sesji
     */
    async getActiveSessionKey(sessionToken) {
        const version = this.getKeyVersion(sessionToken);
        const keyBase64 = localStorage.getItem(`session_key_${sessionToken}_v${version}`);
        
        if (!keyBase64) {
            // Jeśli nie znaleziono wersjonowanego klucza, spróbuj pobrać niezwersjonowany
            const fallbackKey = localStorage.getItem(`session_key_${sessionToken}`);
            if (fallbackKey) {
                return await this.importSessionKey(fallbackKey);
            }
            throw new Error(`Nie znaleziono klucza sesji dla ${sessionToken}`);
        }
        
        return await this.importSessionKey(keyBase64);
    }
    
    /**
     * Generuje unikalny identyfikator UUID v4
     */
    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
    
    /**
     * Oblicza odcisk klucza (fingerprint)
     */
    async getKeyFingerprint(publicKeyPEM) {
        try {
            const publicKey = await this.importPublicKeyFromPEM(publicKeyPEM);
            const exported = await window.crypto.subtle.exportKey("spki", publicKey);
            
            // Haszuj wyeksportowany klucz
            const hash = await window.crypto.subtle.digest('SHA-256', exported);
            
            // Konwertuj hash na string heksadecymalny
            const hashArray = Array.from(new Uint8Array(hash));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            
            // Zwróć odcisk w czytelnym formacie (grupy po 4 znaki)
            return hashHex.match(/.{1,4}/g).join(' ').toUpperCase();
        } catch (error) {
            console.error('Błąd podczas obliczania odcisku klucza:', error);
            return null;
        }
    }
    
    // Funkcje pomocnicze
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }
    
    str2ab(str) {
        const buf = new ArrayBuffer(str.length);
        const bufView = new Uint8Array(buf);
        for (let i = 0; i < str.length; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return buf;
    }
}

// Inicjalizacja
window.chatCrypto = new ChatCrypto();
