/**
 Moduł do obsługi szyfrowania w aplikacji czatu
 */
class ChatCrypto {
    constructor() {
        this.loadKeys();
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
            ["decrypt"]
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
            ["encrypt"]
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
     * Eksportuje/importuje klucz sesji
     */
    async exportSessionKey(sessionKey) {
        const rawKey = await window.crypto.subtle.exportKey("raw", sessionKey);
        return this.arrayBufferToBase64(rawKey);
    }
    
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
     * Szyfruje/deszyfruje klucz sesji
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
     * Szyfruje/deszyfruje wiadomość
     */
    async encryptMessage(message, sessionKey) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoder = new TextEncoder();
        const messageData = encoder.encode(message);
        
        const encryptedMessage = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            sessionKey,
            messageData
        );
        
        return {
            iv: this.arrayBufferToBase64(iv),
            encryptedData: this.arrayBufferToBase64(encryptedMessage)
        };
    }
    
    async decryptMessage(encryptedMessage, sessionKey) {
        const iv = this.base64ToArrayBuffer(encryptedMessage.iv);
        const encryptedData = this.base64ToArrayBuffer(encryptedMessage.encryptedData);
        
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            sessionKey,
            encryptedData
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decryptedData);
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
