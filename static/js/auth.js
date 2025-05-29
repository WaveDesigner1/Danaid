/**
 * auth.js - Oryginalny sposób logowania/rejestracji
 * Zachowuje RSA signature i oryginalną logikę
 */

class AuthManager {
    constructor() {
        this.apiBase = '/api';
        this.rsaKeyPair = null;
        this.publicKey = null;
        this.privateKey = null;
        this.isInitialized = false;
        
        this.init();
    }

    async init() {
        console.log('🔐 AuthManager initializing...');
        
        try {
            // Sprawdź czy użytkownik jest już zalogowany
            await this.checkAuthStatus();
        } catch (error) {
            console.log('⚠️ Not authenticated');
        }
        
        // Generuj RSA keys (ORYGINALNY SPOSÓB)
        await this.generateRSAKeys();
        
        this.isInitialized = true;
        console.log('✅ AuthManager initialized');
    }

    // === RSA KEY MANAGEMENT (ORYGINALNY SPOSÓB) ===
    async generateRSAKeys() {
        try {
            if (!window.crypto || !window.crypto.subtle) {
                console.error('❌ Web Crypto API not available');
                throw new Error('Web Crypto API not supported');
            }

            console.log('🔑 Generating RSA key pair...');
            
            this.rsaKeyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-PSS",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256",
                },
                true,
                ["sign", "verify"]
            );

            // Export public key
            const publicKeyBuffer = await window.crypto.subtle.exportKey(
                "spki",
                this.rsaKeyPair.publicKey
            );
            
            this.publicKey = this.arrayBufferToBase64(publicKeyBuffer);
            
            console.log('✅ RSA key pair generated successfully');
            return true;
            
        } catch (error) {
            console.error('❌ RSA key generation failed:', error);
            throw error;
        }
    }

    async signMessage(message) {
        if (!this.rsaKeyPair) {
            throw new Error('RSA key pair not available');
        }

        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(message);
            
            const signature = await window.crypto.subtle.sign(
                {
                    name: "RSA-PSS",
                    saltLength: 32,
                },
                this.rsaKeyPair.privateKey,
                data
            );
            
            return this.arrayBufferToBase64(signature);
        } catch (error) {
            console.error('❌ Message signing failed:', error);
            throw error;
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

    formatPublicKeyForServer() {
        if (!this.publicKey) {
            throw new Error('Public key not generated');
        }
        
        // Format as PEM
        return `-----BEGIN PUBLIC KEY-----\n${this.publicKey}\n-----END PUBLIC KEY-----`;
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

    // === AUTHENTICATION METHODS (ORYGINALNY SPOSÓB) ===
    
    async register(username, password, publicKey = null) {
        try {
            console.log('📝 Registering user:', username);
            
            // Sprawdź czy RSA keys są wygenerowane
            if (!this.isInitialized || !this.publicKey) {
                console.log('🔑 Waiting for RSA key generation...');
                await this.generateRSAKeys();
            }
            
            // Użyj podanego klucza lub wygenerowanego
            const keyToUse = publicKey || this.formatPublicKeyForServer();
            
            const response = await this.makeRequest('/register', {
                method: 'POST',
                body: JSON.stringify({
                    username: username,
                    password: password,
                    public_key: keyToUse
                }),
            });

            console.log('✅ Registration successful:', response);
            return response;
            
        } catch (error) {
            console.error('❌ Registration failed:', error);
            throw error;
        }
    }

    async login(username, password) {
        try {
            console.log('🔐 Logging in user:', username);

            // Sprawdź czy RSA keys są wygenerowane
            if (!this.isInitialized || !this.rsaKeyPair) {
                console.log('🔑 Waiting for RSA key generation...');
                await this.generateRSAKeys();
            }

            // Generuj RSA signature (ORYGINALNY SPOSÓB - WYMAGANE)
            let signature;
            try {
                signature = await this.signMessage(password);
                console.log('🔑 RSA signature generated');
            } catch (error) {
                console.error('❌ RSA signature generation failed:', error);
                throw new Error('Failed to generate RSA signature: ' + error.message);
            }

            const response = await this.makeRequest('/login', {
                method: 'POST',
                body: JSON.stringify({
                    username: username,
                    password: password,
                    signature: signature  // WYMAGANE!
                }),
            });

            console.log('✅ Login successful:', response);
            
            // Przekierowanie (ORYGINALNY SPOSÓB)
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

            console.log('✅ Logout successful:', response);
            
            // Przekierowanie na stronę główną
            window.location.href = '/';
            
            return response;
            
        } catch (error) {
            console.error('❌ Logout failed:', error);
            // Mimo błędu, przekieruj na stronę główną
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

    // === USER MANAGEMENT ===
    
    async getUserPublicKey(userId) {
        try {
            const response = await this.makeRequest(`/user/${userId}/public_key`);
            return response;
        } catch (error) {
            console.error('❌ Failed to get user public key:', error);
            throw error;
        }
    }

    async getUsers() {
        try {
            const response = await this.makeRequest('/users');
            return response.users || [];
        } catch (error) {
            console.error('❌ Failed to get users:', error);
            throw error;
        }
    }

    async getOnlineUsers() {
        try {
            const response = await this.makeRequest('/online_users');
            return response.online_users || [];
        } catch (error) {
            console.error('❌ Failed to get online users:', error);
            return [];
        }
    }

    // === UI HELPERS ===
    
    showError(message, elementId = 'error-message') {
        console.error('Error:', message);
        
        const errorElement = document.getElementById(elementId);
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.style.display = 'block';
            
            // Auto-hide after 5 seconds
            setTimeout(() => {
                errorElement.style.display = 'none';
            }, 5000);
        } else {
            // Fallback to alert
            alert('Error: ' + message);
        }
    }

    showSuccess(message, elementId = 'success-message') {
        console.log('Success:', message);
        
        const successElement = document.getElementById(elementId);
        if (successElement) {
            successElement.textContent = message;
            successElement.style.display = 'block';
            
            // Auto-hide after 3 seconds
            setTimeout(() => {
                successElement.style.display = 'none';
            }, 3000);
        }
    }

    // === FORM HANDLERS ===
    
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

            if (!username || !password) {
                this.showError('Please enter both username and password');
                return;
            }

            const submitButton = document.getElementById('login-button');
            const originalText = submitButton.textContent;

            try {
                // Disable form during login
                submitButton.disabled = true;
                submitButton.textContent = 'Logging in...';

                await this.login(username, password);
                
            } catch (error) {
                this.showError(error.message);
            } finally {
                // Re-enable form
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

            if (!username || !password) {
                this.showError('Please enter both username and password');
                return;
            }

            if (password.length < 8) {
                this.showError('Password must be at least 8 characters long');
                return;
            }

            const submitButton = form.querySelector('button[type="submit"]');
            const originalText = submitButton.textContent;

            try {
                // Disable form during registration
                submitButton.disabled = true;
                submitButton.textContent = 'Registering...';

                await this.register(username, password, publicKey);
                
                this.showSuccess('Registration successful! Redirecting to login...');
                
                // Clear form
                form.reset();
                
                // Redirect to login page after 2 seconds
                setTimeout(() => {
                    window.location.href = '/login';
                }, 2000);
                
            } catch (error) {
                this.showError(error.message);
            } finally {
                // Re-enable form
                submitButton.disabled = false;
                submitButton.textContent = originalText;
            }
        });

        console.log('✅ Register form handler attached');
    }

    // === AUTO-SETUP ===
    
    autoSetup() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                this.setupLoginForm();
                this.setupRegisterForm();
            });
        } else {
            this.setupLoginForm();
            this.setupRegisterForm();
        }
    }
}

// === GLOBAL INITIALIZATION ===

// Utwórz globalną instancję
window.authManager = new AuthManager();

// Auto-setup form handlers
window.authManager.autoSetup();

// === LEGACY COMPATIBILITY ===

// Globalne funkcje dla kompatybilności ze starym kodem
window.login = (username, password) => window.authManager.login(username, password);
window.register = (username, password, publicKey) => window.authManager.register(username, password, publicKey);
window.logout = () => window.authManager.logout();

// === DEBUG HELPERS ===

window.authDebug = {
    manager: window.authManager,
    checkStatus: () => window.authManager.checkAuthStatus(),
    generateKeys: () => window.authManager.generateRSAKeys(),
    signMessage: (msg) => window.authManager.signMessage(msg),
    getPublicKey: () => window.authManager.publicKey,
    formatKey: () => window.authManager.formatPublicKeyForServer()
};

console.log('🚀 Auth.js loaded successfully');

// === AUTO-GENERATION HELPER ===

// Helper dla formularza rejestracji z auto-generowaniem kluczy
document.addEventListener('DOMContentLoaded', () => {
    const generateButton = document.getElementById('generate-key');
    if (generateButton) {
        generateButton.addEventListener('click', async () => {
            const keyField = document.querySelector('textarea[name="public_key"]');
            const statusDiv = document.getElementById('key-status');
            
            if (!keyField) return;
            
            try {
                generateButton.disabled = true;
                generateButton.textContent = 'Generating...';
                
                if (statusDiv) statusDiv.textContent = 'Generating RSA key pair...';
                
                // Upewnij się że klucze są wygenerowane
                if (!window.authManager.publicKey) {
                    await window.authManager.generateRSAKeys();
                }
                
                // Wstaw sformatowany klucz
                keyField.value = window.authManager.formatPublicKeyForServer();
                
                if (statusDiv) statusDiv.innerHTML = '<span style="color: green;">✅ Key generated successfully!</span>';
                
            } catch (error) {
                console.error('Key generation failed:', error);
                if (statusDiv) statusDiv.innerHTML = '<span style="color: red;">❌ Key generation failed</span>';
            } finally {
                generateButton.disabled = false;
                generateButton.textContent = 'Generate RSA Key Pair';
            }
        });
    }
});
