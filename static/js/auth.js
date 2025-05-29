/**
 * auth.js - ORYGINALNY SYSTEM
 * Użytkownik podaje swój własny klucz prywatny do podpisywania
 */

class AuthManager {
    constructor() {
        this.apiBase = '/api';
        this.userPrivateKey = null;  // Klucz podany przez użytkownika
        this.userPublicKey = null;   // Odpowiadający klucz publiczny
        this.isInitialized = false;
    }

    async init() {
        console.log('🔐 AuthManager initializing...');
        
        // Sprawdź czy użytkownik jest już zalogowany
        try {
            await this.checkAuthStatus();
            console.log('✅ User already authenticated');
        } catch (error) {
            console.log('⚠️ Not authenticated');
        }
        
        this.isInitialized = true;
        console.log('✅ AuthManager initialized');
    }

    // === IMPORT KLUCZA PRYWATNEGO OD UŻYTKOWNIKA ===
    
    async importUserPrivateKey(privateKeyPEM) {
        try {
            console.log('🔑 Importing user private key...');
            
            // Import klucza prywatnego do podpisywania
            const binaryData = this._pemToBinary(privateKeyPEM);
            this.userPrivateKey = await crypto.subtle.importKey(
                "pkcs8",
                binaryData,
                {
                    name: "RSA-PSS",
                    hash: "SHA-256"
                },
                false,
                ["sign"]
            );
            
            console.log('✅ User private key imported successfully');
            
            // Opcjonalnie: zapisz w sessionStorage dla trwałości sesji
            sessionStorage.setItem('user_private_key_pem', privateKeyPEM);
            
            return true;
            
        } catch (error) {
            console.error('❌ Failed to import private key:', error);
            throw new Error('Invalid private key format: ' + error.message);
        }
    }

    async loadStoredPrivateKey() {
        const storedKey = sessionStorage.getItem('user_private_key_pem');
        if (storedKey) {
            try {
                await this.importUserPrivateKey(storedKey);
                console.log('✅ Loaded stored private key');
                return true;
            } catch (error) {
                console.error('❌ Failed to load stored key:', error);
                sessionStorage.removeItem('user_private_key_pem');
            }
        }
        return false;
    }

    // === PODPISYWANIE HASŁA KLUCZEM UŻYTKOWNIKA ===
    
    async signPasswordWithUserKey(password) {
        if (!this.userPrivateKey) {
            throw new Error('No private key loaded. Please provide your private key first.');
        }

        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(password);
            
            const signature = await crypto.subtle.sign(
                {
                    name: "RSA-PSS",
                    saltLength: 32
                },
                this.userPrivateKey,
                data
            );
            
            return this._arrayBufferToBase64(signature);
            
        } catch (error) {
            console.error('❌ Password signing failed:', error);
            throw new Error('Failed to sign password: ' + error.message);
        }
    }

    // === API CALLS ===
    
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

    // === REJESTRACJA - UŻYTKOWNIK PODAJE KLUCZ PUBLICZNY ===
    
    async register(username, password, publicKeyPEM) {
        try {
            console.log('📝 Registering user:', username);
            
            if (!publicKeyPEM) {
                throw new Error('Public key is required for registration');
            }

            const response = await this.makeRequest('/register', {
                method: 'POST',
                body: JSON.stringify({
                    username: username,
                    password: password,
                    public_key: publicKeyPEM
                }),
            });

            console.log('✅ Registration successful:', response);
            return response;
            
        } catch (error) {
            console.error('❌ Registration failed:', error);
            throw error;
        }
    }

    // === LOGOWANIE - ORYGINALNY SPOSÓB ===
    
    async login(username, password, privateKeyPEM = null) {
        try {
            console.log('🔐 Logging in user:', username);

            // Jeśli podano klucz prywatny, załaduj go
            if (privateKeyPEM) {
                await this.importUserPrivateKey(privateKeyPEM);
            } else {
                // Spróbuj załadować z sessionStorage
                const hasStoredKey = await this.loadStoredPrivateKey();
                if (!hasStoredKey) {
                    throw new Error('Private key required for login. Please provide your private key.');
                }
            }

            // Podpisz hasło kluczem użytkownika
            let signature;
            try {
                signature = await this.signPasswordWithUserKey(password);
                console.log('🔑 Password signed with user private key');
            } catch (error) {
                throw new Error('Failed to sign password with your private key: ' + error.message);
            }

            const response = await this.makeRequest('/login', {
                method: 'POST',
                body: JSON.stringify({
                    username: username,
                    password: password,
                    signature: signature
                }),
            });

            console.log('✅ Login successful:', response);
            
            // Przekierowanie
            if (response.status === 'success') {
                window.location.href = '/chat';
            }

            return response;
            
        } catch (error) {
            console.error('❌ Login failed:', error);
            throw error;
        }
    }

    async logout() {
        try {
            console.log('👋 Logging out...');
            
            const response = await this.makeRequest('/logout', {
                method: 'POST',
            });

            // Wyczyść klucze z pamięci
            this.userPrivateKey = null;
            this.userPublicKey = null;
            sessionStorage.removeItem('user_private_key_pem');

            console.log('✅ Logout successful:', response);
            window.location.href = '/';
            
            return response;
            
        } catch (error) {
            console.error('❌ Logout failed:', error);
            // Mimo błędu, wyczyść dane i przekieruj
            this.userPrivateKey = null;
            sessionStorage.removeItem('user_private_key_pem');
            window.location.href = '/';
            throw error;
        }
    }

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

    // === UI HELPERS ===
    
    showError(message, elementId = 'error-message') {
        console.error('Error:', message);
        
        const errorElement = document.getElementById(elementId);
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.style.display = 'block';
            
            setTimeout(() => {
                errorElement.style.display = 'none';
            }, 5000);
        } else {
            alert('Error: ' + message);
        }
    }

    showSuccess(message, elementId = 'success-message') {
        console.log('Success:', message);
        
        const successElement = document.getElementById(elementId);
        if (successElement) {
            successElement.textContent = message;
            successElement.style.display = 'block';
            
            setTimeout(() => {
                successElement.style.display = 'none';
            }, 3000);
        }
    }

    // === FORM HANDLERS - ZMODYFIKOWANE ===
    
    setupLoginForm(formId = 'login-form') {
        const form = document.getElementById(formId);
        if (!form) {
            console.warn(`⚠️ Login form '${formId}' not found`);
            return;
        }

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(form);
            const username = formData.get('username');
            const password = formData.get('password');
            const privateKey = formData.get('private_key'); // NOWE POLE

            if (!username || !password) {
                this.showError('Please enter username and password');
                return;
            }

            if (!privateKey && !sessionStorage.getItem('user_private_key_pem')) {
                this.showError('Please provide your private key');
                return;
            }

            const submitButton = form.querySelector('button[type="submit"]');
            const originalText = submitButton.textContent;

            try {
                submitButton.disabled = true;
                submitButton.textContent = 'Logging in...';

                await this.login(username, password, privateKey);
                
            } catch (error) {
                this.showError(error.message);
            } finally {
                submitButton.disabled = false;
                submitButton.textContent = originalText;
            }
        });

        console.log('✅ Login form handler attached');
    }

    setupRegisterForm(formId = 'register-form') {
        const form = document.getElementById(formId);
        if (!form) {
            console.warn(`⚠️ Register form '${formId}' not found`);
            return;
        }

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(form);
            const username = formData.get('username');
            const password = formData.get('password');
            const publicKey = formData.get('public_key');

            if (!username || !password || !publicKey) {
                this.showError('Please fill in all fields');
                return;
            }

            if (password.length < 8) {
                this.showError('Password must be at least 8 characters long');
                return;
            }

            const submitButton = form.querySelector('button[type="submit"]');
            const originalText = submitButton.textContent;

            try {
                submitButton.disabled = true;
                submitButton.textContent = 'Registering...';

                await this.register(username, password, publicKey);
                
                this.showSuccess('Registration successful! You can now log in.');
                form.reset();
                
                setTimeout(() => {
                    window.location.href = '/login';
                }, 2000);
                
            } catch (error) {
                this.showError(error.message);
            } finally {
                submitButton.disabled = false;
                submitButton.textContent = originalText;
            }
        });

        console.log('✅ Register form handler attached');
    }

    // === SETUP ALTERNATYWNY - dla istniejącego HTML ===
    
    setupAlternativeLogin() {
        // Dla istniejącego przycisku z id="login-button"
        const loginButton = document.getElementById('login-button');
        if (loginButton) {
            loginButton.addEventListener('click', async () => {
                const username = document.querySelector('input[name="username"]')?.value;
                const password = document.querySelector('input[name="password"]')?.value;
                const privateKey = document.querySelector('textarea[name="private_key"]')?.value;

                if (!username || !password) {
                    this.showError('Please enter username and password');
                    return;
                }

                try {
                    loginButton.disabled = true;
                    loginButton.textContent = 'Logging in...';
                    
                    await this.login(username, password, privateKey);
                    
                } catch (error) {
                    this.showError(error.message);
                } finally {
                    loginButton.disabled = false;
                    loginButton.textContent = 'Zaloguj się';
                }
            });
            
            console.log('✅ Alternative login handler attached');
        }
    }

    // === AUTO-SETUP ===
    
    autoSetup() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                this.setupLoginForm();
                this.setupRegisterForm();
                this.setupAlternativeLogin();
            });
        } else {
            this.setupLoginForm();
            this.setupRegisterForm();
            this.setupAlternativeLogin();
        }
    }

    // === UTILITY FUNCTIONS ===
    
    _arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    _base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    _pemToBinary(pem) {
        const lines = pem.split('\n');
        const base64 = lines.slice(1, -1).join('').replace(/\s/g, '');
        return this._base64ToArrayBuffer(base64);
    }

    hasPrivateKey() {
        return !!this.userPrivateKey;
    }

    clearKeys() {
        this.userPrivateKey = null;
        this.userPublicKey = null;
        sessionStorage.removeItem('user_private_key_pem');
        console.log('🧹 User keys cleared');
    }
}

// === GLOBAL INITIALIZATION ===

window.authManager = new AuthManager();
window.authManager.autoSetup();

// === LEGACY COMPATIBILITY ===

window.login = (username, password, privateKey) => window.authManager.login(username, password, privateKey);
window.register = (username, password, publicKey) => window.authManager.register(username, password, publicKey);
window.logout = () => window.authManager.logout();

console.log('🚀 Auth.js loaded - ORIGINAL USER KEY SYSTEM');

// Auto-initialize
window.authManager.init();
