/**
 * E2EEProtocol.js
 * 
 * Implementacja protokołu szyfrowania end-to-end dla aplikacji czatu
 * Obejmuje:
 * - Implementację protokołu X3DH (Extended Triple Diffie-Hellman)
 * - Implementację algorytmu Double Ratchet
 * - Pomocnicze funkcje kryptograficzne
 */

class E2EEProtocol {
    constructor() {
        // Inicjalizacja kluczy
        this.identityKeyPair = null;
        this.signedPreKey = null;
        this.oneTimePreKeys = [];
        this.sessions = {};
        
        // Stałe kryptograficzne
        this.HASH_ALGORITHM = 'SHA-256';
        this.SIGNATURE_ALGORITHM = 'RSASSA-PKCS1-v1_5';
        this.AES_KEY_LENGTH = 256;
        
        this.ready = false;
        this.initialize();
    }
    
    /**
     * Inicjalizacja protokołu
     * Wczytuje lub generuje klucze, jeśli nie istnieją
     */
    async initialize() {
        try {
            // Wczytaj klucz tożsamości
            const storedIdentityKey = localStorage.getItem('identity_key_pair');
            
            if (storedIdentityKey) {
                // Importuj istniejący klucz tożsamości
                this.identityKeyPair = await this.importKeyPair(JSON.parse(storedIdentityKey));
            } else {
                // Wygeneruj nowy klucz tożsamości (RSA dla podpisów)
                this.identityKeyPair = await this.generateIdentityKeyPair();
                
                // Zapisz klucz tożsamości
                localStorage.setItem('identity_key_pair', JSON.stringify(await this.exportKeyPair(this.identityKeyPair)));
            }
            
            // Wczytaj lub wygeneruj klucz pre-key
            const storedSignedPreKey = localStorage.getItem('signed_pre_key');
            
            if (storedSignedPreKey) {
                // Importuj istniejący klucz pre-key
                this.signedPreKey = await this.importKeyPair(JSON.parse(storedSignedPreKey));
            } else {
                // Wygeneruj nowy klucz pre-key (ECDH)
                this.signedPreKey = await this.generateSignedPreKey();
                
                // Zapisz klucz pre-key
                localStorage.setItem('signed_pre_key', JSON.stringify(await this.exportKeyPair(this.signedPreKey)));
            }
            
            // Generuj jednorazowe klucze pre-key (ECDH), jeśli jest to potrzebne
            await this.ensureOneTimePreKeys(20); // Zapewnij że mamy co najmniej 20 jednorazowych kluczy
            
            console.log('Protokół E2EE zainicjalizowany pomyślnie');
            this.ready = true;
        } catch (error) {
            console.error('Błąd inicjalizacji protokołu E2EE:', error);
            throw error;
        }
    }
    
    /**
     * Sprawdza czy protokół jest gotowy do użycia
     */
    isReady() {
        return this.ready;
    }
    
    /**
     * Generuje parę kluczy tożsamości (RSA)
     */
    async generateIdentityKeyPair() {
        try {
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: this.SIGNATURE_ALGORITHM,
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]), // 65537
                    hash: this.HASH_ALGORITHM
                },
                true, // Możliwość eksportu
                ["sign", "verify"] // Możliwości użycia
            );
            
            return keyPair;
        } catch (error) {
            console.error('Błąd generowania kluczy tożsamości:', error);
            throw error;
        }
    }
    
    /**
     * Generuje parę kluczy pre-key podpisaną kluczem tożsamości (ECDH)
     */
    async generateSignedPreKey() {
        try {
            // Wygeneruj klucz ECDH
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true, // Możliwość eksportu
                ["deriveKey", "deriveBits"] // Możliwości użycia
            );
            
            // Eksportuj klucz publiczny do podpisu
            const publicKeyRaw = await window.crypto.subtle.exportKey("raw", keyPair.publicKey);
            
            // Podpisz klucz publiczny kluczem tożsamości
            const signature = await window.crypto.subtle.sign(
                this.SIGNATURE_ALGORITHM,
                this.identityKeyPair.privateKey,
                publicKeyRaw
            );
            
            // Dodaj podpis do obiektu klucza
            return {
                ...keyPair,
                signature: new Uint8Array(signature)
            };
        } catch (error) {
            console.error('Błąd generowania podpisanego klucza pre-key:', error);
            throw error;
        }
    }
    
    /**
     * Generuje jednorazowe klucze pre-key (ECDH)
     */
    async generateOneTimePreKey() {
        try {
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true, // Możliwość eksportu
                ["deriveKey", "deriveBits"] // Możliwości użycia
            );
            
            const keyId = this.generateRandomId();
            
            return {
                keyId: keyId,
                keyPair: keyPair
            };
        } catch (error) {
            console.error('Błąd generowania jednorazowego klucza pre-key:', error);
            throw error;
        }
    }
    
    /**
     * Zapewnia minimalną liczbę jednorazowych kluczy pre-key
     */
    async ensureOneTimePreKeys(minCount) {
        try {
            // Wczytaj zapisane klucze
            const storedKeys = localStorage.getItem('one_time_pre_keys');
            if (storedKeys) {
                const parsedKeys = JSON.parse(storedKeys);
                
                // Importuj klucze
                for (const key of parsedKeys) {
                    const importedKeyPair = await this.importKeyPair(key.keyPair);
                    this.oneTimePreKeys.push({
                        keyId: key.keyId,
                        keyPair: importedKeyPair
                    });
                }
            }
            
            // Sprawdź, czy potrzebujemy więcej kluczy
            const neededKeys = Math.max(0, minCount - this.oneTimePreKeys.length);
            
            if (neededKeys > 0) {
                // Generuj brakujące klucze
                for (let i = 0; i < neededKeys; i++) {
                    this.oneTimePreKeys.push(await this.generateOneTimePreKey());
                }
                
                // Zapisz zaktualizowane klucze
                await this.saveOneTimePreKeys();
            }
            
            console.log(`Dostępne jednorazowe klucze pre-key: ${this.oneTimePreKeys.length}`);
        } catch (error) {
            console.error('Błąd zapewniania jednorazowych kluczy pre-key:', error);
            throw error;
        }
    }
    
    /**
     * Zapisuje jednorazowe klucze pre-key do localStorage
     */
    async saveOneTimePreKeys() {
        try {
            const exportedKeys = [];
            
            for (const key of this.oneTimePreKeys) {
                exportedKeys.push({
                    keyId: key.keyId,
                    keyPair: await this.exportKeyPair(key.keyPair)
                });
            }
            
            localStorage.setItem('one_time_pre_keys', JSON.stringify(exportedKeys));
        } catch (error) {
            console.error('Błąd zapisywania jednorazowych kluczy pre-key:', error);
            throw error;
        }
    }
    
    /**
     * Rozpoczyna nową sesję z drugim użytkownikiem (protokół X3DH)
     */
    async initiateSession(recipientId, recipientPreKeyBundle) {
        try {
            // Dekoduj pakiet kluczy odbiorcy
            const {
                identityKey,
                signedPreKey,
                signedPreKeySignature,
                oneTimePreKey
            } = recipientPreKeyBundle;
            
            // Importuj klucze odbiorcy
            const recipientIdentityKey = await this.importPublicKey(identityKey, this.SIGNATURE_ALGORITHM);
            const recipientSignedPreKey = await this.importPublicKey(signedPreKey, "ECDH");
            
            // Weryfikuj podpis klucza pre-key odbiorcy
            const isValidSignature = await window.crypto.subtle.verify(
                this.SIGNATURE_ALGORITHM,
                recipientIdentityKey,
                this.base64ToArrayBuffer(signedPreKeySignature),
                this.base64ToArrayBuffer(signedPreKey.raw)
            );
            
            if (!isValidSignature) {
                throw new Error('Nieprawidłowy podpis klucza pre-key odbiorcy');
            }
            
            // Wygeneruj efemerydalny klucz (jednorazowy dla tej sesji)
            const ephemeralKeyPair = await window.crypto.subtle.generateKey(
                {
                    name: "ECDH",
                    namedCurve: "P-256"
                },
                true,
                ["deriveKey", "deriveBits"]
            );
            
            // Oblicz klucze DH
            // DH1 = DH(identityKey_A, signedPreKey_B)
            const dh1 = await window.crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: recipientSignedPreKey
                },
                this.identityKeyPair.privateKey,
                256
            );
            
            // DH2 = DH(ephemeralKey_A, identityKey_B)
            const dh2 = await window.crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: recipientIdentityKey
                },
                ephemeralKeyPair.privateKey,
                256
            );
            
            // DH3 = DH(ephemeralKey_A, signedPreKey_B)
            const dh3 = await window.crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: recipientSignedPreKey
                },
                ephemeralKeyPair.privateKey,
                256
            );
            
            // DH4 = DH(ephemeralKey_A, oneTimePreKey_B) - jeśli dostępny
            let dh4 = new Uint8Array();
            
            if (oneTimePreKey) {
                const recipientOneTimePreKey = await this.importPublicKey(oneTimePreKey, "ECDH");
                
                dh4 = await window.crypto.subtle.deriveBits(
                    {
                        name: "ECDH",
                        public: recipientOneTimePreKey
                    },
                    ephemeralKeyPair.privateKey,
                    256
                );
            }
            
            // Łączenie kluczy DH w tajny klucz główny (SK)
            const secretKeyMaterial = this.concatenateArrayBuffers([
                dh1, dh2, dh3, dh4
            ]);
            
            // Obliczamy klucz sesji z materiału kluczowego za pomocą HKDF
            const sessionKey = await this.deriveSessionKey(secretKeyMaterial);
            
            // Zapisz stan sesji
            const sessionId = this.generateSessionId(recipientId);
            
            // Inicjalizacja Double Ratchet z kluczem X3DH
            const initialRootKey = await this.importKey(
                sessionKey,
                "HKDF",
                ["deriveKey"]
            );
            
            const doubleRatchetState = await this.initializeDoubleRatchet(initialRootKey, recipientSignedPreKey);
            
            // Utwórz pakiet inicjalizacyjny do wysłania odbiorcy
            const initPackage = {
                type: 'init',
                senderIdentityKey: await this.exportPublicKey(this.identityKeyPair.publicKey),
                ephemeralKey: await this.exportPublicKey(ephemeralKeyPair.publicKey),
                usedOneTimeKeyId: oneTimePreKey ? oneTimePreKey.keyId : null
            };
            
            // Zapisz sesję
            this.sessions[sessionId] = {
                recipientId: recipientId,
                doubleRatchetState: doubleRatchetState,
                recipientIdentityKey: recipientIdentityKey
            };
            
            // Zapisz stan wszystkich sesji
            this.saveSessions();
            
            return {
                sessionId: sessionId,
                initPackage: initPackage
            };
        } catch (error) {
            console.error('Błąd inicjowania sesji:', error);
            throw error;
        }
    }
    
    /**
     * Odpowiada na inicjację sesji (protokół X3DH)
     */
    async processInitialMessage(senderId, initPackage) {
        try {
            // Dekoduj pakiet inicjalizacyjny
            const {
                senderIdentityKey,
                ephemeralKey,
                usedOneTimeKeyId
            } = initPackage;
            
            // Importuj klucze nadawcy
            const senderIdentityPublicKey = await this.importPublicKey(senderIdentityKey, this.SIGNATURE_ALGORITHM);
            const senderEphemeralPublicKey = await this.importPublicKey(ephemeralKey, "ECDH");
            
            // Znajdź użyty jednorazowy klucz pre-key
            let oneTimePreKeyPair = null;
            
            if (usedOneTimeKeyId) {
                const keyIndex = this.oneTimePreKeys.findIndex(key => key.keyId === usedOneTimeKeyId);
                
                if (keyIndex !== -1) {
                    oneTimePreKeyPair = this.oneTimePreKeys[keyIndex].keyPair;
                    
                    // Usuń użyty klucz jednorazowy
                    this.oneTimePreKeys.splice(keyIndex, 1);
                    await this.saveOneTimePreKeys();
                } else {
                    console.warn('Nie znaleziono jednorazowego klucza o ID:', usedOneTimeKeyId);
                }
            }
            
            // Oblicz klucze DH
            // DH1 = DH(signedPreKey_B, identityKey_A)
            const dh1 = await window.crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: senderIdentityPublicKey
                },
                this.signedPreKey.privateKey,
                256
            );
            
            // DH2 = DH(identityKey_B, ephemeralKey_A)
            const dh2 = await window.crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: senderEphemeralPublicKey
                },
                this.identityKeyPair.privateKey,
                256
            );
            
            // DH3 = DH(signedPreKey_B, ephemeralKey_A)
            const dh3 = await window.crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: senderEphemeralPublicKey
                },
                this.signedPreKey.privateKey,
                256
            );
            
            // DH4 = DH(oneTimePreKey_B, ephemeralKey_A) - jeśli dostępny
            let dh4 = new Uint8Array();
            
            if (oneTimePreKeyPair) {
                dh4 = await window.crypto.subtle.deriveBits(
                    {
                        name: "ECDH",
                        public: senderEphemeralPublicKey
                    },
                    oneTimePreKeyPair.privateKey,
                    256
                );
            }
            
            // Łączenie kluczy DH w tajny klucz główny (SK)
            const secretKeyMaterial = this.concatenateArrayBuffers([
                dh1, dh2, dh3, dh4
            ]);
            
            // Obliczamy klucz sesji z materiału kluczowego za pomocą HKDF
            const sessionKey = await this.deriveSessionKey(secretKeyMaterial);
            
            // Importuj klucz sesji
            const initialRootKey = await this.importKey(
                sessionKey,
                "HKDF",
                ["deriveKey"]
            );
            
            // Inicjalizacja Double Ratchet 
            const doubleRatchetState = await this.initializeDoubleRatchet(initialRootKey, null);
            
            // Zapisz sesję
            const sessionId = this.generateSessionId(senderId);
            
            this.sessions[sessionId] = {
                recipientId: senderId,
                doubleRatchetState: doubleRatchetState,
                recipientIdentityKey: senderIdentityPublicKey
            };
            
            // Zapisz stan wszystkich sesji
            this.saveSessions();
            
            return {
                sessionId: sessionId
            };
        } catch (error) {
            console.error('Błąd przetwarzania początkowej wiadomości:', error);
            throw error;
        }
    }
    
    /**
     * Inicjalizuje algorytm Double Ratchet
     */
    async initializeDoubleRatchet(rootKey, recipientRatchetKey = null) {
        try {
            // Stan początkowy Double Ratchet
            const state = {
                rootKey: rootKey,
                sendingChainKey: null,
                receivingChainKey: null,
                sendingRatchetKey: null,
                receivingRatchetKey: recipientRatchetKey,
                sendingChainKeyCounter: 0,
                receivingChainKeyCounter: 0,
                previousRatchetKeys: [],
                messageKeyCache: {}
            };
            
            // Jeśli nie mamy klucza odbiorcy, generujemy nowy klucz kołowrotka
            if (!recipientRatchetKey) {
                state.sendingRatchetKey = await window.crypto.subtle.generateKey(
                    {
                        name: "ECDH",
                        namedCurve: "P-256"
                    },
                    true,
                    ["deriveKey", "deriveBits"]
                );
                
                // Inicjalizacja łańcucha wysyłania
                const sendingChainResult = await this.kdf(rootKey, new Uint8Array(32)); // 32 bajty zer
                state.rootKey = sendingChainResult.rootKey;
                state.sendingChainKey = sendingChainResult.chainKey;
            }
            
            return state;
        } catch (error) {
            console.error('Błąd inicjalizacji Double Ratchet:', error);
            throw error;
        }
    }
    
    /**
     * Szyfruje wiadomość za pomocą algorytmu Double Ratchet
     */
    async encryptMessage(sessionId, plaintext) {
        try {
            // Pobierz sesję
            const session = this.sessions[sessionId];
            
            if (!session) {
                throw new Error(`Sesja o ID ${sessionId} nie istnieje`);
            }
            
            const state = session.doubleRatchetState;
            
            // Jeśli jest to pierwsza wiadomość lub mamy nowy klucz odbiorcy
            if (!state.sendingChainKey || state.receivingRatchetKey) {
                // Wygeneruj nową parę kluczy Diffie-Hellmana
                if (!state.sendingRatchetKey) {
                    state.sendingRatchetKey = await window.crypto.subtle.generateKey(
                        {
                            name: "ECDH",
                            namedCurve: "P-256"
                        },
                        true,
                        ["deriveKey", "deriveBits"]
                    );
                }
                
                // Oblicz DH kołowrotka
                if (state.receivingRatchetKey) {
                    const dhOutput = await window.crypto.subtle.deriveBits(
                        {
                            name: "ECDH",
                            public: state.receivingRatchetKey
                        },
                        state.sendingRatchetKey.privateKey,
                        256
                    );
                    
                    // Przeprowadź kołowrotek na kluczu głównym
                    const chainResult = await this.kdf(state.rootKey, new Uint8Array(dhOutput));
                    state.rootKey = chainResult.rootKey;
                    state.sendingChainKey = chainResult.chainKey;
                }
                
                // Resetuj licznik
                state.sendingChainKeyCounter = 0;
            }
            
            // Wygeneruj klucz wiadomości
            const messageKey = await this.deriveMessageKey(state.sendingChainKey);
            
            // Zaktualizuj klucz łańcucha wysyłania
            state.sendingChainKey = await this.deriveNextChainKey(state.sendingChainKey);
            state.sendingChainKeyCounter++;
            
            // Zaszyfruj wiadomość
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encoder = new TextEncoder();
            const plaintextBytes = encoder.encode(plaintext);
            
            const ciphertext = await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                messageKey,
                plaintextBytes
            );
            
            // Przygotuj nagłówek
            const header = {
                publicKey: await this.exportPublicKey(state.sendingRatchetKey.publicKey),
                counter: state.sendingChainKeyCounter - 1
            };
            
            // Zapisz zaktualizowany stan sesji
            this.sessions[sessionId].doubleRatchetState = state;
            this.saveSessions();
            
            // Zwróć zaszyfrowaną wiadomość z nagłówkiem
            return {
                header: header,
                ciphertext: this.arrayBufferToBase64(ciphertext),
                iv: this.arrayBufferToBase64(iv)
            };
        } catch (error) {
            console.error('Błąd szyfrowania wiadomości:', error);
            throw error;
        }
    }
    
    /**
     * Deszyfruje wiadomość za pomocą algorytmu Double Ratchet
     */
    async decryptMessage(sessionId, encryptedMessage) {
        try {
            // Pobierz sesję
            const session = this.sessions[sessionId];
            
            if (!session) {
                throw new Error(`Sesja o ID ${sessionId} nie istnieje`);
            }
            
            const state = session.doubleRatchetState;
            
            // Rozpakuj wiadomość
            const { header, ciphertext, iv } = encryptedMessage;
            const { publicKey, counter } = header;
            
            // Sprawdź czy jest to wiadomość od nowego kołowrotka
            const senderRatchetKey = await this.importPublicKey(publicKey, "ECDH");
            let messageKey;
            
            // Sprawdź czy możemy użyć zapisanego klucza wiadomości
            const messageKeyId = `${publicKey.x}_${publicKey.y}_${counter}`;
            
            if (state.messageKeyCache[messageKeyId]) {
                messageKey = state.messageKeyCache[messageKeyId];
                delete state.messageKeyCache[messageKeyId];
            }
            // Jeśli jest to nowy kołowrotek
            else if (!state.receivingRatchetKey || 
                     !this.arePublicKeysEqual(senderRatchetKey, state.receivingRatchetKey)) {
                // Zapisz bieżący klucz odbioru do historii
                if (state.receivingRatchetKey) {
                    state.previousRatchetKeys.push({
                        key: state.receivingRatchetKey,
                        chainKey: state.receivingChainKey,
                        counter: state.receivingChainKeyCounter
                    });
                    
                    // Ogranicz historię do 20 ostatnich kluczy
                    if (state.previousRatchetKeys.length > 20) {
                        state.previousRatchetKeys.shift();
                    }
                }
                
                // Ustaw nowy klucz odbiorcy
                state.receivingRatchetKey = senderRatchetKey;
                
                // Oblicz DH kołowrotka
                if (state.sendingRatchetKey) {
                    const dhOutput = await window.crypto.subtle.deriveBits(
                        {
                            name: "ECDH",
                            public: state.receivingRatchetKey
                        },
                        state.sendingRatchetKey.privateKey,
                        256
                    );
                    
                    // Przeprowadź kołowrotek na kluczu głównym
                    const chainResult = await this.kdf(state.rootKey, new Uint8Array(dhOutput));
                    state.rootKey = chainResult.rootKey;
                    state.receivingChainKey = chainResult.chainKey;
                }
                
                // Resetuj licznik
                state.receivingChainKeyCounter = 0;
                
                // Wygeneruj klucze wiadomości
                messageKey = await this.skipMessageKeys(state, counter);
            }
            // Jeśli jest to przyszła wiadomość w bieżącym łańcuchu
            else if (counter > state.receivingChainKeyCounter) {
                // Wygeneruj klucze wiadomości
                messageKey = await this.skipMessageKeys(state, counter);
            }
            // Jeśli jest to stara wiadomość
            else if (counter < state.receivingChainKeyCounter) {
                // Sprawdź w historii
                messageKey = await this.findPreviousMessageKey(state, senderRatchetKey, counter);
                
                if (!messageKey) {
                    throw new Error('Nie można znaleźć klucza dla starej wiadomości');
                }
            }
            // Standardowy przypadek - wiadomość z bieżącego łańcucha
            else {
                // Wygeneruj klucz wiadomości
                messageKey = await this.deriveMessageKey(state.receivingChainKey);
                
                // Zaktualizuj klucz łańcucha odbierania
                state.receivingChainKey = await this.deriveNextChainKey(state.receivingChainKey);
                state.receivingChainKeyCounter++;
            }
            
            // Deszyfruj wiadomość
            const ciphertextBytes = this.base64ToArrayBuffer(ciphertext);
            const ivBytes = this.base64ToArrayBuffer(iv);
            
            const plaintext = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: ivBytes
                },
                messageKey,
                ciphertextBytes
            );
            
            // Dekoduj tekst
            const decoder = new TextDecoder();
            const decodedText = decoder.decode(plaintext);
            
            // Zapisz zaktualizowany stan sesji
            this.sessions[sessionId].doubleRatchetState = state;
            this.saveSessions();
            
            return decodedText;
        } catch (error) {
            console.error('Błąd deszyfrowania wiadomości:', error);
            throw error;
        }
    }
    
    /**
     * Generuje klucze wiadomości do określonego licznika, zapisując pominięte klucze
     */
    async skipMessageKeys(state, targetCounter) {
        try {
            if (!state.receivingChainKey) {
                throw new Error('Brak klucza łańcucha odbierania');
            }
            
            let chainKey = state.receivingChainKey;
            
            // Zapisz pominięte klucze wiadomości
            while (state.receivingChainKeyCounter < targetCounter) {
                // Wygeneruj klucz wiadomości
                const messageKey = await this.deriveMessageKey(chainKey);
                
                // Zapisz klucz do późniejszego użycia
                const publicKeyExport = await this.exportPublicKey(state.receivingRatchetKey);
                const messageKeyId = `${publicKeyExport.x}_${publicKeyExport.y}_${state.receivingChainKeyCounter}`;
                
                state.messageKeyCache[messageKeyId] = messageKey;
                
                // Przejdź do następnego klucza łańcucha
                chainKey = await this.deriveNextChainKey(chainKey);
                state.receivingChainKeyCounter++;
            }
            
            // Wygeneruj klucz wiadomości docelowej
            const messageKey = await this.deriveMessageKey(chainKey);
            
            // Zaktualizuj stan
            state.receivingChainKey = await this.deriveNextChainKey(chainKey);
            state.receivingChainKeyCounter++;
            
            return messageKey;
        } catch (error) {
            console.error('Błąd pomijania kluczy wiadomości:', error);
            throw error;
        }
    }
    
    /**
     * Znajduje klucz wiadomości w historii kluczy kołowrotka
     */
    async findPreviousMessageKey(state, senderRatchetKey, counter) {
        try {
            // Sprawdź w pamięci podręcznej kluczy wiadomości
            const publicKeyExport = await this.exportPublicKey(senderRatchetKey);
            const messageKeyId = `${publicKeyExport.x}_${publicKeyExport.y}_${counter}`;
            
            if (state.messageKeyCache[messageKeyId]) {
                const messageKey = state.messageKeyCache[messageKeyId];
                delete state.messageKeyCache[messageKeyId];
                return messageKey;
            }
            
            // Poszukaj w historii kluczy kołowrotka
            for (const ratchetState of state.previousRatchetKeys) {
                if (this.arePublicKeysEqual(ratchetState.key, senderRatchetKey)) {
                    // Znaleziono pasujący klucz kołowrotka
                    
                    // Sprawdź, czy wiadomość nie jest zbyt stara
                    if (counter < ratchetState.counter) {
                        return null; // Wiadomość zbyt stara
                    }
                    
                    // Odtwórz łańcuch kluczy
                    let chainKey = ratchetState.chainKey;
                    let currentCounter = ratchetState.counter;
                    
                    // Generuj klucze aż do docelowego licznika
                    while (currentCounter < counter) {
                        // Przejdź do następnego klucza łańcucha
                        chainKey = await this.deriveNextChainKey(chainKey);
                        currentCounter++;
                    }
                    
                    // Wygeneruj klucz wiadomości
                    return await this.deriveMessageKey(chainKey);
                }
            }
            
            // Nie znaleziono odpowiedniego klucza
            return null;
        } catch (error) {
            console.error('Błąd wyszukiwania poprzedniego klucza wiadomości:', error);
            throw error;
        }
    }
    
    /**
     * Generuje klucz sesji z materiału kluczowego za pomocą HKDF
     */
    async deriveSessionKey(keyMaterial) {
        try {
            // Importuj materiał klucza
            const baseKey = await window.crypto.subtle.importKey(
                "raw",
                keyMaterial,
                { name: "HKDF" },
                false,
                ["deriveBits", "deriveKey"]
            );
            
            // Wyprowadź klucz AES-GCM
            const sessionKey = await window.crypto.subtle.deriveKey(
                {
                    name: "HKDF",
                    hash: this.HASH_ALGORITHM,
                    salt: new Uint8Array(32), // 32 bajty zer
                    info: new TextEncoder().encode("X3DH Session Key")
                },
                baseKey,
                {
                    name: "AES-GCM",
                    length: this.AES_KEY_LENGTH
                },
                true,
                ["encrypt", "decrypt"]
            );
            
            return sessionKey;
        } catch (error) {
            console.error('Błąd wyprowadzania klucza sesji:', error);
            throw error;
        }
    }
    
    /**
     * Funkcja KDF dla Double Ratchet
     */
    async kdf(rootKey, dhOutput) {
        try {
            // Importuj materiał klucza
            const baseKey = await window.crypto.subtle.importKey(
                "raw",
                dhOutput,
                { name: "HKDF" },
                false,
                ["deriveBits", "deriveKey"]
            );
            
            // Wyprowadź nowy klucz główny
            const newRootKey = await window.crypto.subtle.deriveBits(
                {
                    name: "HKDF",
                    hash: this.HASH_ALGORITHM,
                    salt: await window.crypto.subtle.exportKey("raw", rootKey),
                    info: new TextEncoder().encode("Root Key")
                },
                baseKey,
                256 // 32 bajty
            );
            
            // Wyprowadź klucz łańcucha
            const chainKey = await window.crypto.subtle.deriveBits(
                {
                    name: "HKDF",
                    hash: this.HASH_ALGORITHM,
                    salt: await window.crypto.subtle.exportKey("raw", rootKey),
                    info: new TextEncoder().encode("Chain Key")
                },
                baseKey,
                256 // 32 bajty
            );
            
            // Importuj klucze
            const newRootKeyObj = await this.importKey(
                newRootKey,
                "HKDF",
                ["deriveKey"]
            );
            
            const chainKeyObj = await this.importKey(
                chainKey,
                "HMAC",
                ["sign"]
            );
            
            return {
                rootKey: newRootKeyObj,
                chainKey: chainKeyObj
            };
        } catch (error) {
            console.error('Błąd funkcji KDF:', error);
            throw error;
        }
    }
    
    /**
     * Wyprowadza następny klucz łańcucha
     */
    async deriveNextChainKey(chainKey) {
        try {
            const hmacResult = await window.crypto.subtle.sign(
                {
                    name: "HMAC",
                    hash: { name: this.HASH_ALGORITHM }
                },
                chainKey,
                new TextEncoder().encode("Chain Key")
            );
            
            return await this.importKey(
                hmacResult,
                "HMAC",
                ["sign"]
            );
        } catch (error) {
            console.error('Błąd wyprowadzania następnego klucza łańcucha:', error);
            throw error;
        }
    }
    
    /**
     * Wyprowadza klucz wiadomości z klucza łańcucha
     */
    async deriveMessageKey(chainKey) {
        try {
            const hmacResult = await window.crypto.subtle.sign(
                {
                    name: "HMAC",
                    hash: { name: this.HASH_ALGORITHM }
                },
                chainKey,
                new TextEncoder().encode("Message Key")
            );
            
            return await this.importKey(
                hmacResult,
                "AES-GCM",
                ["encrypt", "decrypt"]
            );
        } catch (error) {
            console.error('Błąd wyprowadzania klucza wiadomości:', error);
            throw error;
        }
    }
    
    /**
     * Zapisuje stan wszystkich sesji do localStorage
     */
    async saveSessions() {
        try {
            const serializedSessions = {};
            
            for (const [sessionId, session] of Object.entries(this.sessions)) {
                serializedSessions[sessionId] = {
                    recipientId: session.recipientId,
                    recipientIdentityKey: await this.exportPublicKey(session.recipientIdentityKey),
                    doubleRatchetState: await this.serializeDoubleRatchetState(session.doubleRatchetState)
                };
            }
            
            localStorage.setItem('e2ee_sessions', JSON.stringify(serializedSessions));
        } catch (error) {
            console.error('Błąd zapisywania sesji:', error);
        }
    }
    
    /**
     * Wczytuje sesje z localStorage
     */
    async loadSessions() {
        try {
            const serializedSessions = localStorage.getItem('e2ee_sessions');
            
            if (!serializedSessions) {
                return;
            }
            
            const parsedSessions = JSON.parse(serializedSessions);
            
            for (const [sessionId, session] of Object.entries(parsedSessions)) {
                try {
                    this.sessions[sessionId] = {
                        recipientId: session.recipientId,
                        recipientIdentityKey: await this.importPublicKey(session.recipientIdentityKey, this.SIGNATURE_ALGORITHM),
                        doubleRatchetState: await this.deserializeDoubleRatchetState(session.doubleRatchetState)
                    };
                } catch (error) {
                    console.error(`Błąd wczytywania sesji ${sessionId}:`, error);
                }
            }
        } catch (error) {
            console.error('Błąd wczytywania sesji:', error);
        }
    }
    
    /**
     * Serializuje stan Double Ratchet do formatu JSON
     */
    async serializeDoubleRatchetState(state) {
        try {
            const serialized = {
                rootKey: await this.exportKey(state.rootKey),
                sendingChainKey: state.sendingChainKey ? await this.exportKey(state.sendingChainKey) : null,
                receivingChainKey: state.receivingChainKey ? await this.exportKey(state.receivingChainKey) : null,
                sendingRatchetKey: state.sendingRatchetKey ? await this.exportKeyPair(state.sendingRatchetKey) : null,
                receivingRatchetKey: state.receivingRatchetKey ? await this.exportPublicKey(state.receivingRatchetKey) : null,
                sendingChainKeyCounter: state.sendingChainKeyCounter,
                receivingChainKeyCounter: state.receivingChainKeyCounter,
                previousRatchetKeys: [],
                messageKeyCache: {}
            };
            
            // Serializuj poprzednie klucze
            for (const ratchetState of state.previousRatchetKeys) {
                serialized.previousRatchetKeys.push({
                    key: await this.exportPublicKey(ratchetState.key),
                    chainKey: await this.exportKey(ratchetState.chainKey),
                    counter: ratchetState.counter
                });
            }
            
            // Serializuj pamięć podręczną kluczy wiadomości
            for (const [keyId, messageKey] of Object.entries(state.messageKeyCache)) {
                serialized.messageKeyCache[keyId] = await this.exportKey(messageKey);
            }
            
            return serialized;
        } catch (error) {
            console.error('Błąd serializacji stanu Double Ratchet:', error);
            throw error;
        }
    }
    
    /**
     * Deserializuje stan Double Ratchet z formatu JSON
     */
    async deserializeDoubleRatchetState(serialized) {
        try {
            const state = {
                rootKey: await this.importKey(
                    this.base64ToArrayBuffer(serialized.rootKey),
                    "HKDF",
                    ["deriveKey"]
                ),
                sendingChainKey: serialized.sendingChainKey ? await this.importKey(
                    this.base64ToArrayBuffer(serialized.sendingChainKey),
                    "HMAC",
                    ["sign"]
                ) : null,
                receivingChainKey: serialized.receivingChainKey ? await this.importKey(
                    this.base64ToArrayBuffer(serialized.receivingChainKey),
                    "HMAC",
                    ["sign"]
                ) : null,
                sendingRatchetKey: serialized.sendingRatchetKey ? await this.importKeyPair(serialized.sendingRatchetKey) : null,
                receivingRatchetKey: serialized.receivingRatchetKey ? await this.importPublicKey(serialized.receivingRatchetKey, "ECDH") : null,
                sendingChainKeyCounter: serialized.sendingChainKeyCounter,
                receivingChainKeyCounter: serialized.receivingChainKeyCounter,
                previousRatchetKeys: [],
                messageKeyCache: {}
            };
            
            // Deserializuj poprzednie klucze
            for (const ratchetState of serialized.previousRatchetKeys) {
                state.previousRatchetKeys.push({
                    key: await this.importPublicKey(ratchetState.key, "ECDH"),
                    chainKey: await this.importKey(
                        this.base64ToArrayBuffer(ratchetState.chainKey),
                        "HMAC",
                        ["sign"]
                    ),
                    counter: ratchetState.counter
                });
            }
            
            // Deserializuj pamięć podręczną kluczy wiadomości
            for (const [keyId, messageKey] of Object.entries(serialized.messageKeyCache)) {
                state.messageKeyCache[keyId] = await this.importKey(
                    this.base64ToArrayBuffer(messageKey),
                    "AES-GCM",
                    ["encrypt", "decrypt"]
                );
            }
            
            return state;
        } catch (error) {
            console.error('Błąd deserializacji stanu Double Ratchet:', error);
            throw error;
        }
    }
    
    /**
     * Eksportuje klucz publiczny do formatu serializowalnego
     */
    async exportPublicKey(publicKey) {
        try {
            // Określ algorytm klucza
            const algorithm = publicKey.algorithm.name;
            
            if (algorithm === "ECDH") {
                // Dla kluczy ECDH używamy formatu 'raw'
                const rawKey = await window.crypto.subtle.exportKey("raw", publicKey);
                
                // Konwertuj na format JSON-serializowalny
                return {
                    algorithm: algorithm,
                    curve: publicKey.algorithm.namedCurve,
                    raw: this.arrayBufferToBase64(rawKey),
                    x: this.arrayBufferToBase64(rawKey.slice(1, 33)), // X-coordinate
                    y: this.arrayBufferToBase64(rawKey.slice(33, 65))  // Y-coordinate
                };
            } else if (algorithm === this.SIGNATURE_ALGORITHM) {
                // Dla kluczy RSA używamy formatu 'spki'
                const spkiKey = await window.crypto.subtle.exportKey("spki", publicKey);
                
                return {
                    algorithm: algorithm,
                    spki: this.arrayBufferToBase64(spkiKey)
                };
            } else {
                throw new Error(`Nieobsługiwany algorytm klucza: ${algorithm}`);
            }
        } catch (error) {
            console.error('Błąd eksportu klucza publicznego:', error);
            throw error;
        }
    }
    
    /**
     * Importuje klucz publiczny z formatu serializowalnego
     */
    async importPublicKey(keyData, algorithm) {
        try {
            if (!keyData) {
                throw new Error('Brak danych klucza do importu');
            }
            
            if (algorithm === "ECDH") {
                // Importuj klucz ECDH
                const keyBuffer = keyData.raw ? 
                    this.base64ToArrayBuffer(keyData.raw) : 
                    await this.reconstructECPublicKey(keyData.x, keyData.y);
                
                return await window.crypto.subtle.importKey(
                    "raw",
                    keyBuffer,
                    {
                        name: "ECDH",
                        namedCurve: keyData.curve || "P-256"
                    },
                    true,
                    []
                );
            } else if (algorithm === this.SIGNATURE_ALGORITHM) {
                // Importuj klucz RSA
                const keyBuffer = this.base64ToArrayBuffer(keyData.spki);
                
                return await window.crypto.subtle.importKey(
                    "spki",
                    keyBuffer,
                    {
                        name: this.SIGNATURE_ALGORITHM,
                        hash: this.HASH_ALGORITHM
                    },
                    true,
                    ["verify"]
                );
            } else {
                throw new Error(`Nieobsługiwany algorytm klucza: ${algorithm}`);
            }
        } catch (error) {
            console.error('Błąd importu klucza publicznego:', error);
            throw error;
        }
    }
    
    /**
     * Rekonstruuje klucz publiczny EC z współrzędnych X i Y
     */
    async reconstructECPublicKey(x, y) {
        try {
            const xBytes = this.base64ToArrayBuffer(x);
            const yBytes = this.base64ToArrayBuffer(y);
            
            // Utwórz punkt na krzywej (format: 0x04 || X || Y)
            const buffer = new Uint8Array(65);
            buffer[0] = 0x04; // niezkompresowany punkt
            buffer.set(new Uint8Array(xBytes), 1);
            buffer.set(new Uint8Array(yBytes), 33);
            
            return buffer;
        } catch (error) {
            console.error('Błąd rekonstrukcji klucza EC:', error);
            throw error;
        }
    }
    
    /**
     * Eksportuje parę kluczy
     */
    async exportKeyPair(keyPair) {
        try {
            return {
                publicKey: await this.exportPublicKey(keyPair.publicKey),
                privateKey: await this.exportPrivateKey(keyPair.privateKey)
            };
        } catch (error) {
            console.error('Błąd eksportu pary kluczy:', error);
            throw error;
        }
    }
    
    /**
     * Importuje parę kluczy
     */
    async importKeyPair(keyPairData) {
        try {
            // Określ algorytm na podstawie danych
            const algorithm = keyPairData.publicKey.algorithm;
            
            if (algorithm === "ECDH") {
                // Importuj klucz publiczny
                const publicKey = await this.importPublicKey(keyPairData.publicKey, algorithm);
                
                // Importuj klucz prywatny
                const privateKey = await this.importPrivateKey(keyPairData.privateKey, algorithm);
                
                return {
                    publicKey: publicKey,
                    privateKey: privateKey
                };
            } else if (algorithm === this.SIGNATURE_ALGORITHM) {
                // Importuj klucz publiczny
                const publicKey = await this.importPublicKey(keyPairData.publicKey, algorithm);
                
                // Importuj klucz prywatny
                const privateKey = await this.importPrivateKey(keyPairData.privateKey, algorithm);
                
                return {
                    publicKey: publicKey,
                    privateKey: privateKey
                };
            } else {
                throw new Error(`Nieobsługiwany algorytm klucza: ${algorithm}`);
            }
        } catch (error) {
            console.error('Błąd importu pary kluczy:', error);
            throw error;
        }
    }
    
    /**
     * Eksportuje klucz prywatny
     */
    async exportPrivateKey(privateKey) {
        try {
            const algorithm = privateKey.algorithm.name;
            
            if (algorithm === "ECDH") {
                const pkcs8Key = await window.crypto.subtle.exportKey("pkcs8", privateKey);
                
                return {
                    algorithm: algorithm,
                    curve: privateKey.algorithm.namedCurve,
                    pkcs8: this.arrayBufferToBase64(pkcs8Key)
                };
            } else if (algorithm === this.SIGNATURE_ALGORITHM) {
                const pkcs8Key = await window.crypto.subtle.exportKey("pkcs8", privateKey);
                
                return {
                    algorithm: algorithm,
                    pkcs8: this.arrayBufferToBase64(pkcs8Key)
                };
            } else {
                throw new Error(`Nieobsługiwany algorytm klucza: ${algorithm}`);
            }
        } catch (error) {
            console.error('Błąd eksportu klucza prywatnego:', error);
            throw error;
        }
    }
    
    /**
     * Importuje klucz prywatny
     */
    async importPrivateKey(keyData, algorithm) {
        try {
            const keyBuffer = this.base64ToArrayBuffer(keyData.pkcs8);
            
            if (algorithm === "ECDH") {
                return await window.crypto.subtle.importKey(
                    "pkcs8",
                    keyBuffer,
                    {
                        name: "ECDH",
                        namedCurve: keyData.curve || "P-256"
                    },
                    true,
                    ["deriveKey", "deriveBits"]
                );
            } else if (algorithm === this.SIGNATURE_ALGORITHM) {
                return await window.crypto.subtle.importKey(
                    "pkcs8",
                    keyBuffer,
                    {
                        name: this.SIGNATURE_ALGORITHM,
                        hash: this.HASH_ALGORITHM
                    },
                    true,
                    ["sign"]
                );
            } else {
                throw new Error(`Nieobsługiwany algorytm klucza: ${algorithm}`);
            }
        } catch (error) {
            console.error('Błąd importu klucza prywatnego:', error);
            throw error;
        }
    }
    
    /**
     * Eksportuje klucz do formatu serializowalnego
     */
    async exportKey(key) {
        try {
            const keyData = await window.crypto.subtle.exportKey("raw", key);
            return this.arrayBufferToBase64(keyData);
        } catch (error) {
            console.error('Błąd eksportu klucza:', error);
            throw error;
        }
    }
    
    /**
     * Importuje klucz z formatu serializowalnego
     */
    async importKey(keyData, algorithm, usages) {
        try {
            let keyBuffer;
            
            if (typeof keyData === 'string') {
                keyBuffer = this.base64ToArrayBuffer(keyData);
            } else {
                keyBuffer = keyData;
            }
            
            let params = {};
            
            if (algorithm === "HMAC") {
                params = {
                    name: algorithm,
                    hash: this.HASH_ALGORITHM
                };
            } else if (algorithm === "AES-GCM") {
                params = {
                    name: algorithm,
                    length: this.AES_KEY_LENGTH
                };
            } else if (algorithm === "HKDF") {
                params = {
                    name: algorithm,
                    hash: this.HASH_ALGORITHM
                };
            } else {
                throw new Error(`Nieobsługiwany algorytm klucza: ${algorithm}`);
            }
            
            return await window.crypto.subtle.importKey(
                "raw",
                keyBuffer,
                params,
                false,
                usages
            );
        } catch (error) {
            console.error('Błąd importu klucza:', error);
            throw error;
        }
    }
    
    /**
     * Porównuje, czy dwa klucze publiczne są identyczne
     */
    async arePublicKeysEqual(keyA, keyB) {
        try {
            // Eksportuj oba klucze
            const keyAExport = await this.exportPublicKey(keyA);
            const keyBExport = await this.exportPublicKey(keyB);
            
            // Porównaj oba klucze (dokładne porównanie)
            return JSON.stringify(keyAExport) === JSON.stringify(keyBExport);
        } catch (error) {
            console.error('Błąd porównywania kluczy publicznych:', error);
            return false;
        }
    }
    
    /**
     * Generuje losowy identyfikator
     */
    generateRandomId() {
        const array = new Uint8Array(16);
        window.crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    
    /**
     * Generuje identyfikator sesji na podstawie ID odbiorcy
     */
    generateSessionId(recipientId) {
        return `session_${recipientId}`;
    }
    
    /**
     * Łączy bufory bajtów
     */
    concatenateArrayBuffers(buffers) {
        // Oblicz całkowitą długość
        let totalLength = 0;
        for (const buffer of buffers) {
            totalLength += buffer.byteLength;
        }
        
        // Utwórz nowy bufor i skopiuj dane
        const result = new Uint8Array(totalLength);
        let offset = 0;
        
        for (const buffer of buffers) {
            result.set(new Uint8Array(buffer), offset);
            offset += buffer.byteLength;
        }
        
        return result.buffer;
    }
    
    /**
     * Konwertuje ArrayBuffer na Base64
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    /**
     * Konwertuje Base64 na ArrayBuffer
     */
    base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }
    
    /**
     * Tworzy pakiet kluczy pre-key
     */
    async createPreKeyBundle() {
        try {
            // Eksportuj klucz tożsamości
            const identityKey = await this.exportPublicKey(this.identityKeyPair.publicKey);
            
            // Eksportuj podpisany klucz pre-key
            const signedPreKeyPublic = await this.exportPublicKey(this.signedPreKey.publicKey);
            
            // Podpis klucza pre-key
            const signedPreKeySignature = this.arrayBufferToBase64(this.signedPreKey.signature);
            
            // Wybierz losowy jednorazowy klucz pre-key
            let oneTimePreKey = null;
            
            if (this.oneTimePreKeys.length > 0) {
                const randomIndex = Math.floor(Math.random() * this.oneTimePreKeys.length);
                const randomPreKey = this.oneTimePreKeys[randomIndex];
                
                // Eksportuj jednorazowy klucz pre-key
                oneTimePreKey = {
                    keyId: randomPreKey.keyId,
                    publicKey: await this.exportPublicKey(randomPreKey.keyPair.publicKey)
                };
            }
            
            // Utwórz pakiet pre-key
            return {
                identityKey: identityKey,
                signedPreKey: signedPreKeyPublic,
                signedPreKeySignature: signedPreKeySignature,
                oneTimePreKey: oneTimePreKey
            };
        } catch (error) {
            console.error('Błąd tworzenia pakietu pre-key:', error);
            throw error;
        }
    }
    
    /**
     * Pozyskuje pakiet kluczy pre-key dla odbiorcy
     */
    async getPreKeyBundle(recipientId) {
        try {
            // Tutaj powinna być implementacja pobierania pakietu pre-key z serwera
            // Dla uproszczenia, zwracamy przykładowy pakiet
            // W rzeczywistej implementacji będzie to zapytanie do API
            
            const response = await fetch(`/api/user/${recipientId}/pre_key_bundle`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`Błąd pobierania pakietu pre-key: ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('Błąd pozyskiwania pakietu pre-key:', error);
            throw error;
        }
    }
}

// Inicjalizacja i eksport
window.e2eeProtocol = new E2EEProtocol();