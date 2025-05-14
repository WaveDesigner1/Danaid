/**
 * Moduł do obsługi szyfrowania w aplikacji czatu
 */
class ChatCrypto {
    constructor() {
        // Sprawdź czy mamy zapisane klucze
        this.loadKeys();
    }
    
    /**
     * Ładuje klucze z pamięci lokalnej
     */
    async loadKeys() {
        // Sprawdź czy mamy zapisane klucze
        const privateKeyPEM = localStorage.getItem('private_key_pem');
        if (!privateKeyPEM) {
            console.warn('Brak zapisanego klucza prywatnego w localStorage');
            return false;
        }
        
        try {
            // Importuj klucz prywatny
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
        if (!pem.includes("-----BEGIN PRIVATE KEY-----")) {
            throw new Error("Nieprawidłowy format klucza prywatnego");
        }

        const pemContents = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace(/\s+/g, "");

        const binaryDer = this.str2ab(atob(pemContents));

        return await window.crypto.subtle.importKey(
            "pkcs8",
            binaryDer,
            {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256"
            },
            true, // extractable
            ["sign", "decrypt"] // Rozszerzono o decrypt
        );
    }
    
    /**
     * Importuje klucz publiczny z formatu PEM
     */
    async importPublicKeyFromPEM(pem) {
        if (!pem.includes("-----BEGIN PUBLIC KEY-----")) {
            throw new Error("Nieprawidłowy format klucza publicznego");
        }

        const pemContents = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(/\s+/g, "");

        const binaryDer = this.str2ab(atob(pemContents));

        return await window.crypto.subtle.importKey(
            "spki",
            binaryDer,
            {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256"
            },
            true, // extractable
            ["verify", "encrypt"] // Rozszerzono o encrypt
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
            true, // extractable
            ["encrypt", "decrypt"]
        );
    }
    
    /**
     * Eksportuje klucz sesji do formatu, który można przesłać
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
            true, // extractable
            ["encrypt", "decrypt"]
        );
    }
    
    /**
     * Szyfruje klucz sesji kluczem publicznym odbiorcy
     */
    async encryptSessionKey(sessionKeyBase64, recipientPublicKey) {
        // Zamień Base64 na ArrayBuffer
        const sessionKeyData = this.base64ToArrayBuffer(sessionKeyBase64);
        
        // Szyfruj kluczem publicznym odbiorcy
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
     * Deszyfruje klucz sesji zaszyfrowany naszym kluczem publicznym
     */
    async decryptSessionKey(encryptedKeyBase64) {
        // Zamień Base64 na ArrayBuffer
        const encryptedKeyData = this.base64ToArrayBuffer(encryptedKeyBase64);
        
        // Deszyfruj naszym kluczem prywatnym
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
    async encryptMessage(message, sessionKey) {
        // Generuj losowy IV (Initialization Vector)
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        // Konwertuj wiadomość na ArrayBuffer
        const encoder = new TextEncoder();
        const messageData = encoder.encode(message);
        
        // Szyfruj wiadomość
        const encryptedMessage = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            sessionKey,
            messageData
        );
        
        // Zwróć IV i zaszyfrowaną wiadomość w formacie Base64
        return {
            iv: this.arrayBufferToBase64(iv),
            encryptedData: this.arrayBufferToBase64(encryptedMessage)
        };
    }
    
    /**
     * Deszyfruje wiadomość kluczem sesji
     */
    async decryptMessage(encryptedMessage, sessionKey) {
        // Pobierz IV i zaszyfrowane dane
        const iv = this.base64ToArrayBuffer(encryptedMessage.iv);
        const encryptedData = this.base64ToArrayBuffer(encryptedMessage.encryptedData);
        
        // Deszyfruj wiadomość
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            sessionKey,
            encryptedData
        );
        
        // Konwertuj z powrotem na tekst
        const decoder = new TextDecoder();
        return decoder.decode(decryptedData);
    }
    
    /**
     * Podpisuje wiadomość kluczem prywatnym nadawcy
     */
    async signMessage(message) {
        const encoder = new TextEncoder();
        const messageData = encoder.encode(message);
        
        // Podpisz wiadomość
        const signature = await window.crypto.subtle.sign(
            {
                name: "RSASSA-PKCS1-v1_5"
            },
            this.privateKey,
            messageData
        );
        
        return this.arrayBufferToBase64(signature);
    }
    
    /**
     * Weryfikuje podpis wiadomości kluczem publicznym nadawcy
     */
    async verifySignature(message, signature, senderPublicKey) {
        const encoder = new TextEncoder();
        const messageData = encoder.encode(message);
        const signatureData = this.base64ToArrayBuffer(signature);
        
        // Weryfikuj podpis
        return await window.crypto.subtle.verify(
            {
                name: "RSASSA-PKCS1-v1_5"
            },
            senderPublicKey,
            signatureData,
            messageData
        );
    }
    
    /**
     * Tworzy hash wiadomości (do sprawdzania integralności)
     */
    async hashMessage(message) {
        const encoder = new TextEncoder();
        const messageData = encoder.encode(message);
        
        // Oblicz hash SHA-256
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', messageData);
        return this.arrayBufferToBase64(hashBuffer);
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

// Inicjalizacja obiektu ChatCrypto
window.chatCrypto = new ChatCrypto();
