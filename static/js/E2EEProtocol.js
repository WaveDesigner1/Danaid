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
            const publicKeyExport = await this.
