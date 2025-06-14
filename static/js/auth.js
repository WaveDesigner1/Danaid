/**
 * auth.js - Refactored Authentication Frontend - MODULAR VERSION
 * Clean, unified authentication system with CryptoManager integration
 */

// Authentication System Class
class DanaidAuthSystem {
    constructor() {
        this.currentUser = null;
        this.isAuthenticated = false;
        this.authCheckInterval = null;
        this.cryptoManager = null;
        this.cryptoAvailable = false;
        
        // Initialize on load
        this.init();
    }

    // Initialization
    async init() {
        console.log("Initializing Danaid Auth System - Modular Version");
        
        // Check CryptoManager availability
        try {
            if (typeof CryptoManager !== 'undefined') {
                this.cryptoManager = new CryptoManager();
                
                // Verify crypto actually works
                const initResult = await this.cryptoManager.initializeCrypto();
                this.cryptoAvailable = initResult;
                
                if (this.cryptoAvailable) {
                    console.log("CryptoManager initialized successfully");
                } else {
                    console.warn("CryptoManager initialization failed - proceeding without crypto features");
                }
            } else {
                console.warn("CryptoManager not available - crypto features disabled");
                this.cryptoAvailable = false;
            }
        } catch (error) {
            console.error("CryptoManager initialization error:", error);
            this.cryptoAvailable = false;
        }
        
        // Check current authentication status
        await this.checkAuthStatus();
        
        // Set up periodic auth check
        this.setupAuthCheck();
        
        // Initialize page-specific handlers
        this.initPageHandlers();
    }

    initPageHandlers() {
        const path = window.location.pathname;
        
        if (path === '/' || path.includes('index')) {
            this.initLoginPage();
        } else if (path.includes('register')) {
            this.initRegisterPage();
        } else if (path.includes('chat')) {
            this.initChatPage();
        }
    }

    // Authentication Status
    async checkAuthStatus() {
        try {
            const response = await fetch('/api/check_auth', {
                method: 'GET',
                credentials: 'include'
            });

            if (response.ok) {
                const data = await response.json();
                this.currentUser = {
                    id: data.id,
                    user_id: data.user_id,
                    username: data.username,
                    is_admin: data.is_admin,
                    public_key: data.public_key
                };
                this.isAuthenticated = true;
                console.log("User authenticated:", this.currentUser.username);
                return true;
            } else {
                this.currentUser = null;
                this.isAuthenticated = false;
                return false;
            }
        } catch (error) {
            console.error("Auth check error:", error);
            this.currentUser = null;
            this.isAuthenticated = false;
            return false;
        }
    }

    setupAuthCheck() {
        // Check auth status every 5 minutes
        this.authCheckInterval = setInterval(() => {
            this.checkAuthStatus();
        }, 300000);
    }

    // Login Page Handlers
    initLoginPage() {
        console.log("Initializing login page");

        // Login form handler
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }

        // Private key file handler
        const privateKeyFile = document.getElementById('privateKeyFile');
        if (privateKeyFile) {
            privateKeyFile.addEventListener('change', (e) => this.handlePrivateKeyFile(e));
        }

        // Check if already authenticated
        if (this.isAuthenticated) {
            window.location.href = '/chat';
        }
    }

    async handleLogin(event) {
        event.preventDefault();

        const submitButton = document.getElementById('loginSubmit');
        const statusDiv = document.getElementById('loginStatus');
        
        // Disable submit button
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.textContent = 'Logging in...';
        }

        try {
            // Get form data
            const formData = new FormData(event.target);
            const username = formData.get('username');
            const password = formData.get('password');

            if (!username || !password) {
                throw new Error('Username and password are required');
            }

            // Prepare login data
            const loginData = {
                username: username,
                password: password
            };

            // Add digital signature if crypto available
            try {
                if (window.userPrivateKey && this.cryptoAvailable && this.cryptoManager) {
                    const signature = await this.cryptoManager.signPassword(password, window.userPrivateKey);
                    loginData.signature = signature;
                    console.log("Digital signature added to login");
                }
            } catch (sigError) {
                console.warn("Failed to add digital signature:", sigError);
                // Continue without signature
            }

            // Send login request
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include',
                body: JSON.stringify(loginData)
            });

            const result = await response.json();

            if (response.ok && result.status === 'success') {
                this.showStatus(statusDiv, 'Login successful! Redirecting...', 'success');
                
                // Update auth state
                this.currentUser = {
                    id: result.id,
                    user_id: result.user_id,
                    username: result.username,
                    is_admin: result.is_admin
                };
                this.isAuthenticated = true;

                // Redirect to chat
                setTimeout(() => {
                    window.location.href = '/chat';
                }, 1000);

            } else {
                throw new Error(result.error || 'Login failed');
            }

        } catch (error) {
            console.error('Login error:', error);
            this.showStatus(statusDiv, `Login failed: ${error.message}`, 'error');
        } finally {
            // Re-enable submit button
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.textContent = 'Zaloguj się';
            }
        }
    }

    handlePrivateKeyFile(event) {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    window.userPrivateKey = e.target.result;
                    console.log("Private key loaded for digital signatures");
                    
                    // Load key if crypto available
                    if (this.cryptoAvailable && this.cryptoManager) {
                        try {
                            this.cryptoManager.loadPrivateKey(e.target.result);
                        } catch (cryptoError) {
                            console.warn("Failed to load key into crypto manager:", cryptoError);
                        }
                    }
                    
                    // Show success indicator
                    const indicator = document.getElementById('keyLoadIndicator');
                    if (indicator) {
                        indicator.textContent = 'Private key loaded successfully';
                        indicator.className = 'key-indicator success';
                        indicator.style.display = 'block';
                    }
                } catch (error) {
                    console.error("Failed to load private key:", error);
                    
                    // Show error indicator
                    const indicator = document.getElementById('keyLoadIndicator');
                    if (indicator) {
                        indicator.textContent = 'Failed to load private key';
                        indicator.className = 'key-indicator error';
                        indicator.style.display = 'block';
                    }
                }
            };
            reader.readAsText(file);
        }
    }

    // Registration Page Handlers
    initRegisterPage() {
        console.log("Initializing registration page");

        // Registration form handler
        const registerForm = document.getElementById('registerForm');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => this.handleRegister(e));
        }

        // Show crypto status info
        if (!this.cryptoAvailable) {
            this.showCryptoUnavailableMessage();
        }
    }

    showCryptoUnavailableMessage() {
        const registerForm = document.getElementById('registerForm');
        if (!registerForm) return;

        const warningDiv = document.createElement('div');
        warningDiv.className = 'form-group';
        warningDiv.innerHTML = `
            <div class="crypto-warning" style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 5px; margin-bottom: 15px;">
                <strong>Crypto Not Available</strong><br>
                RSA key generation is not available in this browser. 
                You can still register, but advanced crypto features will be limited.
            </div>
        `;
        
        registerForm.insertBefore(warningDiv, registerForm.firstChild);
    }

    // Registration form validation
    validateRegistrationForm(username, password) {
        // Check empty fields
        if (!username || !password) {
            return { valid: false, error: 'All fields are required' };
        }

        // Validate username format
        if (!/^[a-zA-Z0-9_-]{3,20}$/.test(username)) {
            return { valid: false, error: 'Username must be 3-20 characters long and contain only letters, numbers, underscores, or hyphens' };
        }

        // Validate password length
        if (password.length < 8) {
            return { valid: false, error: 'Password must be at least 8 characters long' };
        }

        // Check for uppercase letter
        if (!/[A-Z]/.test(password)) {
            return { valid: false, error: 'Password must contain at least one uppercase letter' };
        }

        // Check for lowercase letter
        if (!/[a-z]/.test(password)) {
            return { valid: false, error: 'Password must contain at least one lowercase letter' };
        }

        // Check for digit
        if (!/[0-9]/.test(password)) {
            return { valid: false, error: 'Password must contain at least one digit' };
        }

        // Check for special character
        if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
            return { valid: false, error: 'Password must contain at least one special character' };
        }

        return { valid: true };
    }

    async handleRegister(event) {
        event.preventDefault();

        const submitButton = event.target.querySelector('button[type="submit"], input[type="submit"]');
        const statusDiv = document.getElementById('status');
        
        // Get form data
        const formData = new FormData(event.target);
        const username = formData.get('username');
        const password = formData.get('password');

        // Validate form data FIRST
        const validation = this.validateRegistrationForm(username, password);
        if (!validation.valid) {
            this.showStatus(statusDiv, validation.error, 'error');
            return;
        }

        // Disable submit button
        if (submitButton) {
            submitButton.disabled = true;
            if (submitButton.tagName === 'BUTTON') {
                submitButton.textContent = 'Registering...';
            } else {
                submitButton.value = 'Registering...';
            }
        }

        try {
            let publicKey = null;
            let privateKey = null;
            
            // Generate RSA keys if crypto available
            if (this.cryptoAvailable && this.cryptoManager) {
                try {
                    this.showStatus(statusDiv, 'Generating RSA keys...', 'info');
                    
                    const keyPair = await this.cryptoManager.generateKeyPair();
                    if (keyPair && keyPair.publicKey && keyPair.privateKey) {
                        publicKey = keyPair.publicKey;
                        privateKey = keyPair.privateKey;
                        
                        this.showStatus(statusDiv, 'RSA keys generated, registering...', 'info');
                    }
                } catch (keyError) {
                    console.warn('Key generation failed during registration:', keyError);
                    this.showStatus(statusDiv, 'Key generation failed, registering without keys...', 'warning');
                }
            }

            // Prepare registration data
            const registrationData = {
                username: username,
                password: password
            };

            // Add public key if generated
            if (publicKey) {
                registrationData.public_key = publicKey;
            }

            // Send registration request
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include',
                body: JSON.stringify(registrationData)
            });

            const result = await response.json();

            if (response.ok && result.status === 'success') {
                this.showStatus(statusDiv, 'Registration successful!', 'success');
                
                // Show download modal if keys were generated
                if (privateKey && publicKey) {
                    this.showDownloadModal(privateKey, publicKey);
                } else {
                    // Redirect if no keys
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 2000);
                }

            } else {
                throw new Error(result.error || 'Registration failed');
            }

        } catch (error) {
            console.error('Registration error:', error);
            this.showStatus(statusDiv, `Registration failed: ${error.message}`, 'error');
        } finally {
            // Re-enable submit button
            if (submitButton) {
                submitButton.disabled = false;
                if (submitButton.tagName === 'BUTTON') {
                    submitButton.textContent = 'Zarejestruj się';
                } else {
                    submitButton.value = 'Zarejestruj się';
                }
            }
        }
    }

    // Modal with download button
    showDownloadModal(privateKey, publicKey) {
        // Create modal
        const modal = document.createElement('div');
        modal.className = 'download-modal';
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(51, 51, 51, 0.85);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 10000;
        `;

        modal.innerHTML = `
            <div class="modal-content" style="
                background: #2a2a2a;
                color:rgb(179, 179, 179);
                padding: 30px;
                border-radius: 8px;
                text-align: center;
                max-width: 400px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
                border: 1px solid #444444;
            ">
                <h3 style="color: #FF9800; margin-bottom: 20px;">Klucze RSA wygenerowane!</h3>
                <p style="margin-bottom: 20px; color: #CCCCCC;">
                    Klucz publiczny został zapisany na serwerze.<br>
                    <strong style="color: #FF9800;">Pobierz klucz prywatny</strong> - będziesz go potrzebować do logowania.
                </p>
                <button id="downloadPrivateKey" class="btn btn-primary" style="
                    background: #FF9800;
                    color: #333333;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 16px;
                    margin-right: 10px;
                    font-weight: bold;
                    transition: background-color 0.3s, transform 0.2s;
                ">
                    Pobierz klucz prywatny
                </button>
                <button id="skipDownload" class="btn btn-secondary" style="
                    background: #666666;
                    color: #FFFFFF;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 16px;
                    transition: background-color 0.3s;
                ">
                    Pomiń
                </button>
            </div>
        `;

        // Add hover effects
        const styleSheet = document.createElement('style');
        styleSheet.textContent = `
            #downloadPrivateKey:hover {
                background: #F57C00 !important;
                transform: translateY(-2px);
            }
            
            #skipDownload:hover {
                background: #777777 !important;
            }
        `;
        document.head.appendChild(styleSheet);

        document.body.appendChild(modal);

        // Event handlers
        document.getElementById('downloadPrivateKey').addEventListener('click', () => {
            this.downloadPrivateKey(privateKey);
            this.closeModalAndRedirect(modal);
        });

        document.getElementById('skipDownload').addEventListener('click', () => {
            this.closeModalAndRedirect(modal);
        });

        // Click outside modal
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                this.closeModalAndRedirect(modal);
            }
        });
    }

    downloadPrivateKey(privateKey) {
        const blob = new Blob([privateKey], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'danaid_private_key.pem';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    closeModalAndRedirect(modal) {
        modal.remove();
        setTimeout(() => {
            window.location.href = '/';
        }, 500);
    }

    // Chat Page Handlers
    initChatPage() {
        console.log("Initializing chat page authentication");

        // Check authentication
        if (!this.isAuthenticated) {
            console.log("Not authenticated, redirecting to login");
            window.location.href = '/';
            return;
        }

        // Setup logout handler
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.handleLogout());
        }

        // Display user info
        this.displayUserInfo();
    }

    displayUserInfo() {
        if (!this.currentUser) return;

        // Update username display
        const usernameElements = document.querySelectorAll('.current-username');
        usernameElements.forEach(element => {
            element.textContent = this.currentUser.username;
        });

        // Update user ID display
        const userIdElements = document.querySelectorAll('.current-user-id');
        userIdElements.forEach(element => {
            element.textContent = this.currentUser.user_id;
        });

        // Show admin indicator if applicable
        if (this.currentUser.is_admin) {
            const adminElements = document.querySelectorAll('.admin-indicator');
            adminElements.forEach(element => {
                element.style.display = 'inline-block';
            });
        }
    }

    // Logout Handling
    async handleLogout() {
        try {
            console.log("Initiating logout");

            // Send logout request
            const response = await fetch('/api/logout', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const result = await response.json();

            if (response.ok && result.status === 'success') {
                console.log("Logout successful");
                
                // Clear auth state
                this.currentUser = null;
                this.isAuthenticated = false;
                
                // Clear crypto manager if available
                if (this.cryptoAvailable && this.cryptoManager) {
                    try {
                        this.cryptoManager.clear();
                    } catch (error) {
                        console.warn("Failed to clear crypto manager:", error);
                    }
                }
                
                // Clear any stored keys
                delete window.userPrivateKey;
                delete window.generatedKeys;
                
                // Clear auth check interval
                if (this.authCheckInterval) {
                    clearInterval(this.authCheckInterval);
                }
                
                // Redirect to login
                window.location.href = '/';

            } else {
                throw new Error(result.message || 'Logout failed');
            }

        } catch (error) {
            console.error('Logout error:', error);
            // Force redirect even if logout request fails
            window.location.href = '/';
        }
    }

    // Utility Methods
    showStatus(element, message, type) {
        if (!element) return;

        element.textContent = message;
        element.className = `status-message ${type}`;
        element.style.display = 'block';

        // Auto-hide after 5 seconds for success messages
        if (type === 'success') {
            setTimeout(() => {
                element.style.display = 'none';
            }, 5000);
        }
    }

    // Public API
    getCurrentUser() {
        return this.currentUser;
    }

    isUserAuthenticated() {
        return this.isAuthenticated;
    }

    async refreshAuth() {
        return await this.checkAuthStatus();
    }

    getCryptoManager() {
        return this.cryptoAvailable ? this.cryptoManager : null;
    }

    getCryptoStatus() {
        return {
            available: this.cryptoAvailable,
            manager: !!this.cryptoManager,
            stats: this.cryptoAvailable && this.cryptoManager ? 
                this.cryptoManager.getStats() : null
        };
    }
}

// Global Initialization

// Create global auth system instance
window.authSystem = new DanaidAuthSystem();

// Utility functions for backward compatibility
window.checkAuth = function() {
    return window.authSystem.checkAuthStatus();
};

window.logout = function() {
    return window.authSystem.handleLogout();
};

window.getCurrentUser = function() {
    return window.authSystem.getCurrentUser();
};

window.checkCryptoStatus = function() {
    const status = window.authSystem.getCryptoStatus();
    console.log('Crypto Status:', status);
    return status;
};

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        console.log("Auth system ready - Modular version with proper validation order");
    });
} else {
    console.log("Auth system ready - Modular version with proper validation order");
}

console.log("Danaid Auth System loaded successfully - Registration flow fixed");