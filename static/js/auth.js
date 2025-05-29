// Complete auth.js with all original functions + dual encryption modifications

// =================
// GLOBAL VARIABLES
// =================
let isRegistering = false;
let isLoggingIn = false;

// =================
// REGISTRATION FUNCTIONS
// =================

async function register() {
    if (isRegistering) return;
    
    const username = document.getElementById('reg-username')?.value.trim();
    const password = document.getElementById('reg-password')?.value;
    const confirmPassword = document.getElementById('reg-confirm-password')?.value;
    
    // Validation
    if (!username || !password || !confirmPassword) {
        showError('Please fill all fields');
        return;
    }
    
    if (password !== confirmPassword) {
        showError('Passwords do not match');
        return;
    }
    
    if (password.length < 8) {
        showError('Password must be at least 8 characters long');
        return;
    }
    
    if (username.length < 3) {
        showError('Username must be at least 3 characters long');
        return;
    }
    
    isRegistering = true;
    updateRegisterButton('Generating keys...');
    
    try {
        // Initialize crypto manager if not already done
        if (!window.cryptoManager) {
            window.cryptoManager = new CryptoManager();
        }
        
        // Generate RSA key pair
        showProgress('Generating RSA key pair (2048-bit)...');
        const keyPair = await window.cryptoManager.generateKeyPair();
        
        showProgress('Exporting keys...');
        const publicKeyPEM = await window.cryptoManager.exportPublicKey(keyPair);
        const privateKeyPEM = await window.cryptoManager.exportPrivateKey(keyPair);
        
        showProgress('Registering with server...');
        
        // Register with server
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                password,
                public_key: publicKeyPEM
            })
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            showProgress('Registration successful! Preparing private key download...');
            
            // Download private key file
            const blob = new Blob([privateKeyPEM], { type: 'application/x-pem-file' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${username}_private_key.pem`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            showSuccess(`
                🎉 Registration Successful!<br><br>
                <strong>User ID:</strong> ${result.user_id}<br>
                <strong>Username:</strong> ${username}<br><br>
                ⚠️ <strong>IMPORTANT:</strong> Your private key file has been downloaded.<br>
                Keep it safe - you'll need it to login!<br><br>
                You will now be redirected to the login page.
            `);
            
            // Clear form
            document.getElementById('reg-username').value = '';
            document.getElementById('reg-password').value = '';
            document.getElementById('reg-confirm-password').value = '';
            
            // Redirect to login after delay
            setTimeout(() => {
                window.location.href = '/';
            }, 5000);
            
        } else {
            showError('Registration failed: ' + (result.error || result.message || 'Unknown error'));
        }
        
    } catch (error) {
        console.error('Registration error:', error);
        showError('Registration failed: ' + error.message);
    } finally {
        isRegistering = false;
        updateRegisterButton('Register');
        hideProgress();
    }
}

function updateRegisterButton(text) {
    const btn = document.getElementById('register-btn');
    if (btn) {
        btn.textContent = text;
        btn.disabled = isRegistering;
    }
}

// =================
// LOGIN FUNCTIONS
// =================

async function login() {
    if (isLoggingIn) return;
    
    const username = document.getElementById('username')?.value.trim();
    const password = document.getElementById('password')?.value;
    const pemFile = document.getElementById('pem-file')?.files[0];
    
    if (!username || !password) {
        showError('Please enter username and password');
        return;
    }
    
    if (!pemFile) {
        showError('Please select your private key file (.pem)');
        return;
    }
    
    isLoggingIn = true;
    updateLoginButton('Logging in...');
    
    try {
        showProgress('Reading private key file...');
        
        // Read and validate private key file
        const privateKeyPEM = await pemFile.text();
        
        if (!validatePrivateKeyFormat(privateKeyPEM)) {
            throw new Error('Invalid private key file format');
        }
        
        showProgress('Validating private key...');
        
        // Initialize crypto manager
        if (!window.cryptoManager) {
            window.cryptoManager = new CryptoManager();
        }
        
        // Test key import to validate format
        try {
            await window.cryptoManager.importPrivateKey(privateKeyPEM);
        } catch (keyError) {
            throw new Error('Private key file is corrupted or invalid');
        }
        
        showProgress('Authenticating with server...');
        
        // SIMPLIFIED LOGIN - Skip signature verification for now
        // In production version, this would include RSA signature verification
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                password
                // signature: signature_would_go_here_in_production
            })
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            showProgress('Login successful! Loading encryption keys...');
            
            // Store credentials in session
            sessionStorage.setItem('private_key_pem', privateKeyPEM);
            sessionStorage.setItem('user_id', result.user_id);
            sessionStorage.setItem('username', username);
            sessionStorage.setItem('is_admin', result.is_admin);
            
            // Load crypto manager with keys
            await window.cryptoManager.loadKeys();
            
            showSuccess('Login successful! Redirecting to chat...');
            
            // Clear form for security
            document.getElementById('username').value = '';
            document.getElementById('password').value = '';
            document.getElementById('pem-file').value = '';
            
            // Redirect to chat
            setTimeout(() => {
                window.location.href = '/chat.html';
            }, 1500);
            
        } else {
            showError('Login failed: ' + (result.error || result.message || 'Invalid credentials'));
        }
        
    } catch (error) {
        console.error('Login error:', error);
        showError('Login failed: ' + error.message);
    } finally {
        isLoggingIn = false;
        updateLoginButton('Login');
        hideProgress();
    }
}

function updateLoginButton(text) {
    const btn = document.getElementById('login-btn');
    if (btn) {
        btn.textContent = text;
        btn.disabled = isLoggingIn;
    }
}

// MODIFIED: Enhanced secure logout with dual encryption cleanup
async function logout() {
    const confirmed = confirm(
        "🔐 SECURITY LOGOUT\n\n" +
        "This will:\n" +
        "• Clear all chat encryption keys from server\n" +
        "• Remove all session keys from this device\n" +
        "• Require new key exchange for future chats\n" +
        "• Maximize your privacy and security\n\n" +
        "Continue with secure logout?"
    );
    
    if (!confirmed) return;
    
    try {
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.textContent = 'Clearing keys...';
            logoutBtn.disabled = true;
        }
        
        showProgress('Clearing encryption keys...');
        
        // Clear client-side crypto data immediately
        if (window.cryptoManager) {
            window.cryptoManager.clearAllKeys();
            console.log("🧹 Client-side crypto data cleared");
        }
        
        // Clear all session storage
        sessionStorage.clear();
        
        // Clear any chat manager data
        if (window.chatManager) {
            window.chatManager.cleanup();
        }
        
        showProgress('Notifying server...');
        
        // Server-side logout with aggressive key cleanup
        const response = await fetch('/api/logout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        if (response.ok) {
            const result = await response.json();
            
            if (result.status === 'success') {
                showProgress('Logout completed successfully');
                
                setTimeout(() => {
                    alert(
                        `🔐 SECURE LOGOUT COMPLETED\n\n` +
                        `✅ Cleared encryption keys for ${result.encryption_keys_cleared || 0} chat sessions\n` +
                        `✅ All client-side data removed\n` +
                        `✅ Your privacy is protected\n\n` +
                        `You can now safely close this browser or use it for other purposes.`
                    );
                    
                    window.location.href = '/';
                }, 1000);
                
            } else if (result.status === 'warning') {
                console.warn("⚠️ Logout completed with warnings:", result.error);
                
                setTimeout(() => {
                    alert(
                        `⚠️ LOGOUT WARNING\n\n` +
                        `You have been logged out and client-side data cleared, but there may have been an issue clearing server-side encryption keys.\n\n` +
                        `For maximum security:\n` +
                        `• Close all browser windows\n` +
                        `• Clear browser data manually\n` +
                        `• Avoid using this device for sensitive communications`
                    );
                    
                    window.location.href = '/';
                }, 1000);
            }
        } else {
            throw new Error(`Server logout failed: ${response.status}`);
        }
        
    } catch (error) {
        console.error("❌ Logout error:", error);
        
        // Emergency client-side cleanup
        try {
            sessionStorage.clear();
            if (window.cryptoManager) {
                window.cryptoManager.clearAllKeys();
            }
            if (window.chatManager) {
                window.chatManager.cleanup();
            }
        } catch (cleanupError) {
            console.error("❌ Emergency cleanup error:", cleanupError);
        }
        
        alert(
            `❌ LOGOUT ERROR\n\n` +
            `There was an error during logout: ${error.message}\n\n` +
            `SECURITY MEASURES TAKEN:\n` +
            `✅ Client-side data has been cleared\n` +
            `⚠️ Server-side keys may still exist\n\n` +
            `RECOMMENDATIONS:\n` +
            `• Close all browser windows immediately\n` +
            `• Clear all browser data manually\n` +
            `• Do not use this device for sensitive communications\n` +
            `• Contact support if this persists`
        );
        
        // Force redirect even on error
        setTimeout(() => {
            window.location.href = '/';
        }, 2000);
        
    } finally {
        hideProgress();
    }
}

// =================
// AUTHENTICATION CHECKING
// =================

async function checkAuth() {
    try {
        const response = await fetch('/api/check_auth');
        if (response.ok) {
            return await response.json();
        }
        return null;
    } catch (error) {
        console.error('Auth check error:', error);
        return null;
    }
}

async function requireAuth() {
    const auth = await checkAuth();
    if (!auth) {
        alert('Please login to access this page');
        window.location.href = '/';
        return false;
    }
    return auth;
}

// =================
// ADMIN FUNCTIONS
// =================

async function checkAdminAccess() {
    const auth = await checkAuth();
    if (!auth || !auth.is_admin) {
        alert('Admin access required');
        window.location.href = '/';
        return false;
    }
    return true;
}

// =================
// VALIDATION FUNCTIONS
// =================

function validatePrivateKeyFormat(pemData) {
    if (!pemData || typeof pemData !== 'string') {
        return false;
    }
    
    // Check for proper PEM format
    const hasBeginMarker = pemData.includes('-----BEGIN PRIVATE KEY-----') || 
                          pemData.includes('-----BEGIN RSA PRIVATE KEY-----');
    const hasEndMarker = pemData.includes('-----END PRIVATE KEY-----') || 
                        pemData.includes('-----END RSA PRIVATE KEY-----');
    
    if (!hasBeginMarker || !hasEndMarker) {
        return false;
    }
    
    // Check for reasonable length (RSA 2048-bit keys are usually 1600+ chars)
    if (pemData.length < 1000) {
        return false;
    }
    
    // Check for base64 content between markers
    const lines = pemData.split('\n');
    const contentLines = lines.slice(1, -1);
    const base64Pattern = /^[A-Za-z0-9+/=]*$/;
    
    for (const line of contentLines) {
        if (line.trim() && !base64Pattern.test(line.trim())) {
            return false;
        }
    }
    
    return true;
}

function validateUsername(username) {
    if (!username || username.length < 3 || username.length > 20) {
        return false;
    }
    
    // Allow alphanumeric and underscores only
    const usernamePattern = /^[a-zA-Z0-9_]+$/;
    return usernamePattern.test(username);
}

function validatePassword(password) {
    if (!password || password.length < 8) {
        return false;
    }
    
    // Check for at least one number and one letter
    const hasNumber = /\d/.test(password);
    const hasLetter = /[a-zA-Z]/.test(password);
    
    return hasNumber && hasLetter;
}

// =================
// UI HELPER FUNCTIONS
// =================

function showError(message) {
    hideProgress();
    
    const errorDiv = document.getElementById('error-message') || createMessageDiv('error-message', 'error');
    errorDiv.innerHTML = `❌ ${message}`;
    errorDiv.style.display = 'block';
    
    // Auto-hide after 10 seconds
    setTimeout(() => {
        errorDiv.style.display = 'none';
    }, 10000);
}

function showSuccess(message) {
    hideProgress();
    
    const successDiv = document.getElementById('success-message') || createMessageDiv('success-message', 'success');
    successDiv.innerHTML = `✅ ${message}`;
    successDiv.style.display = 'block';
    
    // Auto-hide after 8 seconds
    setTimeout(() => {
        successDiv.style.display = 'none';
    }, 8000);
}

function showProgress(message) {
    const progressDiv = document.getElementById('progress-message') || createMessageDiv('progress-message', 'progress');
    progressDiv.innerHTML = `⏳ ${message}`;
    progressDiv.style.display = 'block';
}

function hideProgress() {
    const progressDiv = document.getElementById('progress-message');
    if (progressDiv) {
        progressDiv.style.display = 'none';
    }
}

function createMessageDiv(id, className) {
    const div = document.createElement('div');
    div.id = id;
    div.className = `message ${className}`;
    div.style.display = 'none';
    
    // Insert after form or at top of body
    const form = document.querySelector('form') || document.body;
    if (form.tagName === 'FORM') {
        form.parentNode.insertBefore(div, form.nextSibling);
    } else {
        form.insertBefore(div, form.firstChild);
    }
    
    return div;
}

// =================
// FILE HANDLING
// =================

function setupFileInput() {
    const fileInput = document.getElementById('pem-file');
    if (!fileInput) return;
    
    fileInput.addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (!file) return;
        
        // Validate file extension
        if (!file.name.toLowerCase().endsWith('.pem')) {
            showError('Please select a .pem file');
            fileInput.value = '';
            return;
        }
        
        // Validate file size (reasonable limits)
        if (file.size > 10000 || file.size < 1000) {
            showError('Private key file size seems incorrect');
            fileInput.value = '';
            return;
        }
        
        // Update UI to show file selected
        const label = document.querySelector('label[for="pem-file"]');
        if (label) {
            label.textContent = `✅ ${file.name}`;
            label.style.color = 'green';
        }
    });
}

// =================
// SESSION MANAGEMENT
// =================

function getStoredUserInfo() {
    return {
        user_id: sessionStorage.getItem('user_id'),
        username: sessionStorage.getItem('username'),
        is_admin: sessionStorage.getItem('is_admin') === 'true',
        has_private_key: !!sessionStorage.getItem('private_key_pem')
    };
}

function clearStoredUserInfo() {
    const keysToRemove = [
        'user_id', 'username', 'is_admin', 'private_key_pem'
    ];
    
    keysToRemove.forEach(key => {
        sessionStorage.removeItem(key);
    });
    
    // Also clear any session keys
    Object.keys(sessionStorage).forEach(key => {
        if (key.startsWith('session_key_')) {
            sessionStorage.removeItem(key);
        }
    });
}

// =================
// FORM ENHANCEMENT
// =================

function setupFormValidation() {
    // Real-time username validation
    const usernameInput = document.getElementById('username') || document.getElementById('reg-username');
    if (usernameInput) {
        usernameInput.addEventListener('input', function() {
            const username = this.value.trim();
            const isValid = validateUsername(username);
            
            this.style.borderColor = username ? (isValid ? 'green' : 'red') : '';
            
            if (username && !isValid) {
                showError('Username must be 3-20 characters, letters/numbers/underscore only');
            }
        });
    }
    
    // Real-time password validation
    const passwordInput = document.getElementById('password') || document.getElementById('reg-password');
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            const password = this.value;
            const isValid = validatePassword(password);
            
            this.style.borderColor = password ? (isValid ? 'green' : 'red') : '';
            
            if (password && !isValid) {
                showError('Password must be 8+ characters with at least one letter and one number');
            }
        });
    }
