/**
 * auth.js - Danaid Chat Authentication System
 * Dostosowany do istniejących formularzy HTML
 * Kompatybilny z Railway deployment
 */

class DanaidAuthSystem {
    constructor() {
        this.apiBase = '/api';
        this.userPrivateKey = null;
        this.userPublicKey = null;
        this.isInitialized = false;
        this.keyPair = null;
        
        // Konfiguracja kryptograficzna
        this.RSA_CONFIG = {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        };
        
        this.SIGNING_CONFIG = {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        };
        
        console.log('🔐 Danaid Auth System initialized');
    }

    async init() {
        console.log('🔄 Initializing authentication system...');
        
        try {
            // Sprawdź wsparcie Web Crypto API
            if (!window.crypto || !window.crypto.subtle) {
                throw new Error('Web Crypto API not supported');
            }
            
            // Sprawdź czy użytkownik jest już zalogowany
            await this.checkAuthStatus();
            console.log('✅ User already authenticated');
            
        } catch (error) {
            console.log('⚠️ Not authenticated:', error.message);
        }
        
        this.isInitialized = true;
        this.setupEventHandlers();
        this.createDownloadModal();
        console.log('✅ Authentication system ready');
    }

    // === MODAL DO POBIERANIA KLUCZA ===
    
    createDownloadModal() {
        // Sprawdź czy modal już istnieje
        if (document.getElementById('key-download-modal')) {
            return;
        }

        const modalHTML = `
            <div id="key-download-modal" style="
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background-color: rgba(0, 0, 0, 0.8);
                z-index: 1000;
                justify-content: center;
                align-items: center;
            ">
                <div style="
                    background-color: #444444;
                    border-radius: 8px;
                    padding: 30px;
                    max-width: 500px;
                    width: 90%;
                    text-align: center;
                    color: #FFFFFF;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
                ">
                    <h2 style="color: #FF9800; margin-bottom: 20px;">🎉 Rejestracja zakończona!</h2>
                    
                    <div style="
                        background-color: rgba(255, 193, 7, 0.1);
                        border: 1px solid #FFC107;
                        border-radius: 4px;
                        padding: 20px;
                        margin: 20px 0;
                        text-align: left;
                    ">
                        <h3 style="color: #FFC107; margin-top: 0;">⚠️ WAŻNE - Pobierz swój klucz prywatny</h3>
                        <p>Twój klucz prywatny zostanie teraz pobrany. <strong>To jedyna okazja!</strong></p>
                        <ul style="margin: 10px 0; padding-left: 20px;">
                            <li>Zachowaj ten plik w bezpiecznym miejscu</li>
                            <li>Będzie potrzebny przy każdym logowaniu</li>
                            <li>Bez niego nie będziesz mógł się zalogować</li>
                            <li>Nigdy nie udostępniaj go nikomu</li>
                        </ul>
                    </div>
                    
                    <button id="download-key-btn" style="
                        background-color: #FF9800;
                        color: #333333;
                        border: none;
                        padding: 15px 30px;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 16px;
                        font-weight: bold;
                        margin: 10px;
                        transition: background-color 0.3s;
                    ">📥 Pobierz klucz prywatny</button>
                    
                    <button id="continue-to-login-btn" style="
                        background-color: #4CAF50;
                        color: white;
                        border: none;
                        padding: 15px 30px;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 16px;
                        font-weight: bold;
                        margin: 10px;
                        transition: background-color 0.3s;
                        display: none;
                    ">✅ Przejdź do logowania</button>
                    
                    <p id="download-status" style="
                        margin-top: 15px;
                        font-size: 14px;
                        color: #FFC107;
                    "></p>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', modalHTML);
        
        // Event listenery dla modalu
        document.getElementById('download-key-btn').addEventListener('click', () => {
            this.downloadStoredKey();
        });
        
        document.getElementById('continue-to-login-btn').addEventListener('click', () => {
            this.hideDownloadModal();
            window.location.href = '/';
        });
        
        console.log('✅ Download modal created');
    }
    
    showDownloadModal(privateKeyPEM, username) {
        // Zapisz klucz do pobrania
        this.pendingDownload = {
            privateKeyPEM: privateKeyPEM,
            username: username
        };
        
        const modal = document.getElementById('key-download-modal');
        const downloadBtn = document.getElementById('download-key-btn');
        const continueBtn = document.getElementById('continue-to-login-btn');
        const status = document.getElementById('download-status');
        
        // Reset stanu
        downloadBtn.style.display = 'inline-block';
        continueBtn.style.display = 'none';
        status.textContent = 'Kliknij przycisk powyżej, aby pobrać swój klucz prywatny.';
        
        modal.style.display = 'flex';
    }
    
    hideDownloadModal() {
        const modal = document.getElementById('key-download-modal');
        modal.style.display = 'none';
        this.pendingDownload = null;
    }
    
    downloadStoredKey() {
        if (!this.pendingDownload) {
            console.error('No pending download');
            return;
        }
        
        const { privateKeyPEM, username } = this.pendingDownload;
        
        // Pobierz plik
        this.downloadPrivateKey(privateKeyPEM, username);
        
        // Aktualizuj UI
        const downloadBtn = document.getElementById('download-key-btn');
        const continueBtn = document.getElementById('continue-to-login-btn');
        const status = document.getElementById('download-status');
        
        downloadBtn.style.display = 'none';
        continueBtn.style.display = 'inline-block';
        status.innerHTML = `
            <span style="color: #4CAF50;">✅ Klucz pobrany: ${username}_private_key.pem</span><br>
            <small>Sprawdź folder Downloads i zachowaj plik w bezpiecznym miejscu.</small>
        `;
        
        console.log('✅ Key download completed');
    }

    // === GENEROWANIE KLUCZY RSA ===
    
    async generateKeyPair() {
        console.log('🔑 Generating RSA key pair...');
        
        try {
            this.keyPair = await crypto.subtle.generateKey(
                this.RSA_CONFIG,
                true, // extractable
                ["encrypt", "decrypt"]
            );
            
            console.log('✅ RSA key pair generated successfully');
            return this.keyPair;
            
        } catch (error) {
            console.error('❌ Key generation failed:', error);
            throw new Error('Failed to generate cryptographic keys: ' + error.message);
        }
    }

    async generateSigningKeyPair() {
        console.log('🔑 Generating RSA signing key pair...');
        
        try {
            const signingKeyPair = await crypto.subtle.generateKey(
                this.SIGNING_CONFIG,
                true, // extractable
                ["sign", "verify"]
            );
            
            console.log('✅ RSA signing key pair generated');
            return signingKeyPair;
            
        } catch (error) {
            console.error('❌ Signing key generation failed:', error);
            throw new Error('Failed to generate signing keys: ' + error.message);
        }
    }

    // === EKSPORT KLUCZY DO PEM ===
    
    async exportPublicKeyToPEM(publicKey) {
        try {
            const exported = await crypto.subtle.exportKey("spki", publicKey);
            return this.arrayBufferToPEM(exported, 'PUBLIC KEY');
        } catch (error) {
            console.error('❌ Public key export failed:', error);
            throw new Error('Failed to export public key');
        }
    }

    async exportPrivateKeyToPEM(privateKey) {
        try {
            const exported = await crypto.subtle.exportKey("pkcs8", privateKey);
            return this.arrayBufferToPEM(exported, 'PRIVATE KEY');
        } catch (error) {
            console.error('❌ Private key export failed:', error);
            throw new Error('Failed to export private key');
        }
    }

    // === IMPORT KLUCZY Z PEM ===
    
    async importPrivateKeyFromPEM(pemData) {
        try {
            console.log('🔑 Importing private key from PEM...');
            const binaryData = this.pemToBinary(pemData);
            
            const privateKey = await crypto.subtle.importKey(
                "pkcs8",
                binaryData,
                this.SIGNING_CONFIG,
                false,
                ["sign"]
            );
            
            console.log('✅ Private key imported successfully');
            return privateKey;
            
        } catch (error) {
            console.error('❌ Private key import failed:', error);
            throw new Error('Invalid private key format: ' + error.message);
        }
    }

    // === PODPISYWANIE CYFROWE ===
    
    async signPassword(password, privateKey) {
        try {
            console.log('🔏 Signing password with private key...');
            
            const encoder = new TextEncoder();
            const data = encoder.encode(password);
            
            const signature = await crypto.subtle.sign(
                "RSASSA-PKCS1-v1_5",
                privateKey,
                data
            );
            
            const signatureBase64 = this.arrayBufferToBase64(signature);
            console.log('✅ Password signed successfully');
            
            return signatureBase64;
            
        } catch (error) {
            console.error('❌ Password signing failed:', error);
            throw new Error('Failed to sign password: ' + error.message);
        }
    }

    // === REJESTRACJA ===
    
    async register(username, password) {
        try {
            console.log('📝 Starting registration for:', username);
            
            // Walidacja danych
            if (!username || !password) {
                throw new Error('Username and password are required');
            }
            
            if (password.length < 8) {
                throw new Error('Password must be at least 8 characters long');
            }
            
            if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/.test(password)) {
                throw new Error('Password must contain uppercase, lowercase, number and special character');
            }
            
            // Generuj pary kluczy
            const encryptionKeyPair = await this.generateKeyPair();
            const signingKeyPair = await this.generateSigningKeyPair();
            
            // Eksportuj klucze do PEM
            const publicKeyPEM = await this.exportPublicKeyToPEM(encryptionKeyPair.publicKey);
            const privateKeyPEM = await this.exportPrivateKeyToPEM(signingKeyPair.privateKey);
            
            // Wyślij żądanie rejestracji
            const response = await this.makeRequest('/register', {
                method: 'POST',
                body: JSON.stringify({
                    username: username,
                    password: password,
                    public_key: publicKeyPEM
                })
            });
            
            if (response.status === 'success') {
                console.log('✅ Registration successful, user_id:', response.user_id);
                
                // Pokaż modal do pobierania klucza
                this.showDownloadModal(privateKeyPEM, username);
                
                return {
                    success: true,
                    user_id: response.user_id,
                    message: 'Registration successful!',
                    privateKey: privateKeyPEM
                };
            } else {
                throw new Error(response.error || 'Registration failed');
            }
            
        } catch (error) {
            console.error('❌ Registration failed:', error);
            throw error;
        }
    }

    // === LOGOWANIE ===
    
    async login(username, password, privateKeyPEM) {
        try {
            console.log('🔐 Starting login for:', username);
            
            if (!username || !password) {
                throw new Error('Username and password are required');
            }
            
            if (!privateKeyPEM) {
                throw new Error('Private key is required for authentication');
            }
            
            // Import klucza prywatnego
            const privateKey = await this.importPrivateKeyFromPEM(privateKeyPEM);
            
            // Podpisz hasło
            const signature = await this.signPassword(password, privateKey);
            
            // Wyślij żądanie logowania
            const response = await this.makeRequest('/login', {
                method: 'POST',
                body: JSON.stringify({
                    username: username,
                    password: password,
                    signature: signature
                })
            });
            
            if (response.status === 'success') {
                console.log('✅ Login successful');
                
                // Zapisz klucz prywatny w sessionStorage
                sessionStorage.setItem('user_private_key_pem', privateKeyPEM);
                sessionStorage.setItem('user_id', response.user_id);
                sessionStorage.setItem('username', username);
                sessionStorage.setItem('is_admin', response.is_admin);
                sessionStorage.setItem('isLoggedIn', 'true');
                this.userPrivateKey = privateKey;
                
                // Przekieruj do chatu
                setTimeout(() => {
                    window.location.href = '/chat';
                }, 1000);
                
                return response;
                
            } else {
                throw new Error(response.error || 'Login failed');
            }
            
        } catch (error) {
            console.error('❌ Login failed:', error);
            throw error;
        }
    }

    // === WYLOGOWANIE ===
    
    async logout() {
        try {
            console.log('👋 Logging out...');
            
            // Wyślij żądanie wylogowania
            await this.makeRequest('/api/logout', {
                method: 'POST'
            });
            
            // Wyczyść dane lokalne
            this.clearUserData();
            
            console.log('✅ Logout successful');
            window.location.href = '/';
            
        } catch (error) {
            console.error('❌ Logout error:', error);
            // Mimo błędu, wyczyść dane i przekieruj
            this.clearUserData();
            window.location.href = '/';
        }
    }

    clearUserData() {
        // Wyczyść sessionStorage
        sessionStorage.removeItem('user_private_key_pem');
        sessionStorage.removeItem('user_id');
        sessionStorage.removeItem('username');
        sessionStorage.removeItem('is_admin');
        
        // Wyczyść zmienne
        this.userPrivateKey = null;
        this.userPublicKey = null;
        this.keyPair = null;
        
        console.log('🧹 User data cleared');
    }

    // === SPRAWDZANIE STATUSU AUTORYZACJI ===
    
    async checkAuthStatus() {
        try {
            const response = await this.makeRequest('/check_auth');
            console.log('✅ Auth status:', response);
            return response;
        } catch (error) {
            console.log('⚠️ Auth check failed:', error);
            throw error;
        }
    }

    // === POBIERANIE KLUCZA PRYWATNEGO ===
    
    downloadPrivateKey(privateKeyPEM, username) {
        const blob = new Blob([privateKeyPEM], { type: 'application/x-pem-file' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `${username}_private_key.pem`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        URL.revokeObjectURL(url);
        
        console.log('💾 Private key downloaded:', a.download);
    }

    // === OBSŁUGA PLIKÓW PEM ===
    
    async readFileAsPEM(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            
            reader.onload = (event) => {
                const content = event.target.result;
                
                // Walidacja formatu PEM
                if (!content.includes('-----BEGIN') || !content.includes('-----END')) {
                    reject(new Error('Invalid PEM file format'));
                    return;
                }
                
                resolve(content);
            };
            
            reader.onerror = () => {
                reject(new Error('Failed to read file'));
            };
            
            reader.readAsText(file);
        });
    }

    // === ŻĄDANIA API ===
    
    async makeRequest(endpoint, options = {}) {
        const url = `${this.apiBase}${endpoint}`;
        
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'same-origin',
        };

        const finalOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers,
            },
        };

        try {
            console.log(`📡 API Request: ${options.method || 'GET'} ${url}`);
            const response = await fetch(url, finalOptions);
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || `HTTP ${response.status}`);
            }

            return data;
            
        } catch (error) {
            console.error(`❌ API Error for ${endpoint}:`, error);
            throw error;
        }
    }

    // === UI HELPERS ===
    
    showMessage(message, isError = false, elementId = 'login-status') {
        console.log(isError ? 'Error:' : 'Success:', message);
        
        const targetElement = document.getElementById(elementId) || 
                            document.getElementById('status') ||
                            document.getElementById('login-status');
        
        if (targetElement) {
            targetElement.textContent = message;
            targetElement.style.display = 'block';
            targetElement.style.color = isError ? '#f44336' : '#4caf50';
            targetElement.style.backgroundColor = isError ? 'rgba(244, 67, 54, 0.1)' : 'rgba(76, 175, 80, 0.1)';
            targetElement.style.border = `1px solid ${isError ? '#f44336' : '#4caf50'}`;
            targetElement.style.padding = '10px';
            targetElement.style.borderRadius = '4px';
            targetElement.style.marginTop = '10px';
            
            // Auto-hide po 5 sekundach
            setTimeout(() => {
                targetElement.style.display = 'none';
            }, 5000);
        } else {
            // Fallback na alert
            alert((isError ? 'Error: ' : 'Success: ') + message);
        }
    }

    // === EVENT HANDLERS ===
    
    setupEventHandlers() {
        console.log('🔧 Setting up event handlers...');
        
        // === LOGOWANIE ===
        const loginButton = document.getElementById('login-button');
        if (loginButton) {
            loginButton.addEventListener('click', (e) => this.handleLogin(e));
            console.log('✅ Login button handler attached');
        }
        
        // === REJESTRACJA ===
        const registerForm = document.getElementById('registerForm');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => this.handleRegister(e));
            console.log('✅ Register form handler attached');
        }
        
        console.log('✅ Event handlers setup complete');
    }

    async handleLogin(e) {
        e.preventDefault();
        
        const username = document.getElementById('username')?.value;
        const password = document.getElementById('password')?.value;
        const pemFile = document.getElementById('pem-file')?.files[0];
        const loginButton = document.getElementById('login-button');
        
        if (!username || !password) {
            this.showMessage('Please enter username and password', true);
            return;
        }
        
        if (!pemFile) {
            this.showMessage('Please select your private key file (.pem)', true);
            return;
        }
        
        const originalText = loginButton?.textContent || 'Zaloguj się';
        
        try {
            if (loginButton) {
                loginButton.disabled = true;
                loginButton.textContent = 'Logowanie...';
            }
            
            // Wczytaj klucz prywatny z pliku
            const privateKeyPEM = await this.readFileAsPEM(pemFile);
            
            // Wykonaj logowanie
            await this.login(username, password, privateKeyPEM);
            
            this.showMessage('Login successful! Redirecting to chat...');
            
        } catch (error) {
            this.showMessage(error.message, true);
        } finally {
            if (loginButton) {
                loginButton.disabled = false;
                loginButton.textContent = originalText;
            }
        }
    }

    async handleRegister(e) {
        e.preventDefault();
        
        const username = document.getElementById('username')?.value;
        const password = document.getElementById('password')?.value;
        const submitButton = e.target.querySelector('button[type="submit"]');
        
        if (!username || !password) {
            this.showMessage('Please fill in all fields', true, 'status');
            return;
        }
        
        const originalText = submitButton?.textContent || 'Zarejestruj się';
        
        try {
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = 'Generowanie kluczy...';
            }
            
            const result = await this.register(username, password);
            
            this.showMessage('Registration successful! Please download your private key.', false, 'status');
            
        } catch (error) {
            this.showMessage(error.message, true, 'status');
        } finally {
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.textContent = originalText;
            }
        }
    }

    // === UTILITY FUNCTIONS ===
    
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    pemToBinary(pem) {
        const lines = pem.split('\n');
        const base64 = lines.slice(1, -1).join('').replace(/\s/g, '');
        return this.base64ToArrayBuffer(base64);
    }

    arrayBufferToPEM(buffer, label) {
        const base64 = this.arrayBufferToBase64(buffer);
        const chunks = base64.match(/.{1,64}/g) || [];
        return `-----BEGIN ${label}-----\n${chunks.join('\n')}\n-----END ${label}-----`;
    }
}

// === GLOBALNA INICJALIZACJA ===

window.danaidAuth = new DanaidAuthSystem();

// Auto-inicjalizacja po załadowaniu DOM
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.danaidAuth.init();
    });
} else {
    window.danaidAuth.init();
}

// Legacy compatibility dla istniejących wywołań
window.login = (username, password, privateKey) => window.danaidAuth.login(username, password, privateKey);
window.register = (username, password) => window.danaidAuth.register(username, password);
window.logout = () => window.danaidAuth.logout();

console.log('🚀 Danaid Auth System loaded - E2EE Authentication Ready - Railway Compatible');

// === HYBRID LOGOUT SYSTEM ===

/**
 * Hybrid Logout - próbuje JavaScript API, fallback na HTML
 */
async function hybridLogout() {
    console.log('🔄 Starting hybrid logout...');
    
    const logoutBtn = document.getElementById('logout-btn');
    const logoutText = document.getElementById('logout-text');
    const originalText = logoutText ? logoutText.textContent : 'Wyloguj';
    
    try {
        // Sprawdź czy JavaScript Auth jest dostępny
        if (!window.danaidAuth) {
            console.warn('⚠️ JavaScript Auth not available, using fallback');
            throw new Error('danaidAuth not loaded');
        }
        
        if (typeof window.danaidAuth.logout !== 'function') {
            console.warn('⚠️ logout() method not available, using fallback');
            throw new Error('logout method not found');
        }
        
        // Zaktualizuj UI - pokaż loading
        if (logoutBtn) logoutBtn.disabled = true;
        if (logoutText) logoutText.textContent = 'Wylogowywanie...';
        
        console.log('🔓 Attempting JavaScript logout...');
        
        // Spróbuj mechanizm B (JavaScript API)
        await window.danaidAuth.logout();
        
        console.log('✅ JavaScript logout successful');
        
    } catch (error) {
        console.warn('❌ JavaScript logout failed:', error);
        console.log('🔄 Falling back to HTML logout...');
        
        // Przywróć UI
        if (logoutBtn) logoutBtn.disabled = false;
        if (logoutText) logoutText.textContent = 'Przekierowywanie...';
        
        // Fallback na mechanizm A (HTML)
        setTimeout(() => {
            window.location.href = '/logout';
        }, 500); // Krótkie opóźnienie dla UX
        
    } finally {
        // Cleanup - przywróć UI po 3 sekundach (safety)
        setTimeout(() => {
            if (logoutBtn) logoutBtn.disabled = false;
            if (logoutText) logoutText.textContent = originalText;
        }, 3000);
    }
}

/**
 * Backup function - fallback w przypadku problemów z hybridLogout
 */
function emergencyLogout() {
    console.log('🚨 Emergency logout - direct redirect');
    window.location.href = '/logout';
}

/**
 * Setup hybrid logout po załadowaniu DOM
 */
function setupHybridLogout() {
    const logoutBtn = document.getElementById('logout-btn');
    
    if (logoutBtn) {
        // Usuń stary event listener jeśli istnieje
        logoutBtn.onclick = null;
        
        // Dodaj nowy event listener
        logoutBtn.addEventListener('click', hybridLogout);
        
        console.log('✅ Hybrid logout button configured');
    } else {
        console.warn('⚠️ Logout button not found, using emergency fallback');
        
        // Fallback - znajdź przycisk po klasie
        const fallbackBtn = document.querySelector('.btn-danger');
        if (fallbackBtn && fallbackBtn.textContent.includes('Wyloguj')) {
            fallbackBtn.addEventListener('click', (e) => {
                e.preventDefault();
                hybridLogout();
            });
            console.log('✅ Fallback logout button configured');
        }
    }
}

// Globalny error handler dla logout
function setupHybridLogout() {
    console.log('🔧 Setting up hybrid logout...');
    
    let logoutBtn = document.getElementById('logout-btn');
    
    if (logoutBtn) {
        // Usuń stary event listener jeśli istnieje
        logoutBtn.onclick = null;
        
        // Dodaj nowy event listener
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('🔴 LOGOUT BUTTON CLICKED!');
            hybridLogout();
        });
        
        // Mark button as configured
        logoutBtn._hasHybridListener = true;
        
        console.log('✅ Hybrid logout button configured (by ID)');
        return true;
        
    } else {
        console.warn('⚠️ Logout button #logout-btn not found, trying fallback...');
        
        // POPRAWIONY FALLBACK - bardziej precyzyjny
        const allDangerButtons = document.querySelectorAll('.btn-danger');
        console.log(`🔍 Found ${allDangerButtons.length} .btn-danger buttons`);
        
        let logoutButtonFound = false;
        
        allDangerButtons.forEach((btn, index) => {
            const btnText = btn.textContent.trim();
            console.log(`   Button ${index}: "${btnText}"`);
            
            // Sprawdź czy to przycisk wylogowania
            if (btnText.includes('Wyloguj') && !btn._hasHybridListener) {
                btn.addEventListener('click', (e) => {
                    e.preventDefault();
                    console.log('🔴 FALLBACK LOGOUT BUTTON CLICKED!');
                    hybridLogout();
                });
                
                btn._hasHybridListener = true;
                logoutButtonFound = true;
                
                console.log(`✅ Hybrid logout configured on fallback button ${index}`);
            }
        });
        
        if (!logoutButtonFound) {
            console.error('❌ No logout button found!');
            return false;
        }
        
        return true;
    }
}

// POPRAWIONY Auto-setup z wielokrotnym retry
let setupAttempts = 0;
const maxSetupAttempts = 5;

function attemptHybridLogoutSetup() {
    setupAttempts++;
    console.log(`🔄 Hybrid logout setup attempt ${setupAttempts}/${maxSetupAttempts}`);
    
    const success = setupHybridLogout();
    
    if (!success && setupAttempts < maxSetupAttempts) {
        // Retry po coraz dłuższym czasie
        const delay = setupAttempts * 500; // 500ms, 1s, 1.5s, 2s, 2.5s
        console.log(`⏰ Retrying in ${delay}ms...`);
        
        setTimeout(attemptHybridLogoutSetup, delay);
    } else if (success) {
        console.log('✅ Hybrid logout setup successful!');
        setupLogoutErrorHandling();
    } else {
        console.error('❌ Failed to setup hybrid logout after all attempts');
        
        // EMERGENCY FALLBACK - dodaj global click handler
        document.addEventListener('click', (e) => {
            if (e.target.closest('.btn-danger') && 
                e.target.textContent.includes('Wyloguj')) {
                e.preventDefault();
                console.log('🚨 EMERGENCY LOGOUT HANDLER!');
                hybridLogout();
            }
        });
        
        console.log('🚨 Emergency global click handler added');
    }
}

// === AUTO-SETUP Z POPRAWKAMI ===

// Setup po załadowaniu DOM
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(attemptHybridLogoutSetup, 100); // Małe opóźnienie
    });
} else {
    // DOM już załadowany - setup natychmiast i backup
    setTimeout(attemptHybridLogoutSetup, 100);
}

// DODATKOWE backup setup (na wszelki wypadek)
setTimeout(() => {
    if (setupAttempts === 0) {
        console.log('🔄 Force hybrid logout setup...');
        attemptHybridLogoutSetup();
    }
}, 2000);

/**
 * Setup error handling dla logout
 */
function setupLogoutErrorHandling() {
    window.addEventListener('error', (event) => {
        if (event.error && event.error.message && event.error.message.includes('logout')) {
            console.error('🚨 Global logout error detected:', event.error);
            emergencyLogout();
        }
    });
    
    console.log('🛡️ Logout error handling configured');
}

console.log('✅ Enhanced hybrid logout system loaded with timing fixes');
