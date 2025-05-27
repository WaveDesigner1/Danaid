/**
 * auth.js - Zoptymalizowany Login Handler
 * Scalenie: user_script.js + register_send.js (częściowo)
 * Redukcja: 200 → 100 linii kodu
 */

document.addEventListener('DOMContentLoaded', function() {
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('registerForm');
  
  if (loginForm) initLogin();
  if (registerForm) initRegister();
});

// === LOGIN ===
function initLogin() {
  const loginButton = document.getElementById('login-button');
  const loginForm = document.getElementById('login-form');
  
  const handleLogin = async () => {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const pemFile = document.getElementById('pem-file').files[0];
    
    const status = document.getElementById('login-status') || createStatusDiv();
    status.style.display = 'block';
    status.textContent = 'Logging in...';
    
    // Validation
    if (!username || !password || !pemFile) {
      status.textContent = 'Please fill all fields and select PEM file';
      return;
    }
    
    try {
      // Load private key
      const privateKeyPEM = await pemFile.text();
      sessionStorage.setItem('private_key_pem', privateKeyPEM);
      
      // Import key for signing
      const privateKey = await importSigningKey(privateKeyPEM);
      
      // Sign password
      const signature = await signData(privateKey, password);
      
      // Send login request
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, signature })
      });
      
      const result = await response.json();
      
      if (result.status === 'success') {
        // Save session data
        sessionStorage.setItem('user_id', result.user_id);
        sessionStorage.setItem('username', username);
        sessionStorage.setItem('is_admin', result.is_admin);
        sessionStorage.setItem('isLoggedIn', 'true');
        localStorage.setItem('isLoggedIn', 'true');
        
        status.innerHTML = '✅ Login successful! Redirecting...';
        status.style.color = '#4CAF50';
        
        setTimeout(() => {
          window.location.href = '/chat';
        }, 1500);
      } else {
        const errorMsg = getErrorMessage(result.code) || result.message || 'Login failed';
        status.textContent = errorMsg;
        status.style.color = '#F44336';
      }
    } catch (error) {
      console.error('Login error:', error);
      status.textContent = getErrorMessage(error.message) || 'Login error occurred';
      status.style.color = '#F44336';
    }
  };
  
  loginButton?.addEventListener('click', handleLogin);
  loginForm?.addEventListener('submit', (e) => {
    e.preventDefault();
    handleLogin();
  });
}

// === REGISTER ===
function initRegister() {
  const registerForm = document.getElementById('registerForm');
  
  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const status = document.getElementById('status') || createStatusDiv();
    
    status.style.display = 'block';
    status.innerHTML = '🔄 Processing registration...';
    
    // Validation
    if (!username || username.length < 3) {
      showStatus('Username must be at least 3 characters', 'error');
      return;
    }
    
    if (!isValidPassword(password)) {
      showStatus('Password must be at least 8 characters with uppercase, digit, and special character', 'error');
      return;
    }
    
    try {
      status.innerHTML = '🔑 Generating cryptographic keys...';
      
      // Generate RSA key pair
      const keyPair = await generateKeyPair();
      const publicKeyPEM = await exportPublicKey(keyPair.publicKey);
      const privateKeyPEM = await exportPrivateKey(keyPair.privateKey);
      
      // Prepare download
      const privateKeyBlob = new Blob([privateKeyPEM], { type: 'application/x-pem-file' });
      const privateKeyURL = URL.createObjectURL(privateKeyBlob);
      
      status.innerHTML = '📤 Sending registration data...';
      
      // Register
      const response = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, public_key: publicKeyPEM })
      });
      
      const result = await response.json();
      
      if (response.ok && result.status === 'success') {
        showStatus(`
          <div style="text-align: center;">
            <h3>✅ Registration successful!</h3>
            <p><strong>Your ID: <span style="color: #FF9800; font-size: 1.2em;">${result.user_id}</span></strong></p>
            <p>⚠️ <strong>Download your private key now!</strong></p>
            <a href="${privateKeyURL}" download="${username}_private_key.pem" class="btn btn-success" style="margin: 10px 0;">
              📥 Download Private Key
            </a>
            <p><a href="/" style="color: #FF9800;">➡️ Go to Login</a></p>
          </div>
        `, 'success');
        
        setTimeout(() => window.location.href = '/', 10000);
      } else {
        showStatus(getErrorMessage(result.code) || result.message || 'Registration failed', 'error');
      }
    } catch (error) {
      console.error('Registration error:', error);
      showStatus('Registration error: ' + error.message, 'error');
    }
  });
}

// === CRYPTO HELPERS ===
async function importSigningKey(pem) {
  const pemContents = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  
  const binaryDer = base64ToArrayBuffer(pemContents);
  
  return await window.crypto.subtle.importKey(
    "pkcs8", binaryDer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false, ["sign"]
  );
}

async function signData(privateKey, data) {
  const dataBuffer = new TextEncoder().encode(data);
  const signature = await window.crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    privateKey, dataBuffer
  );
  return arrayBufferToBase64(signature);
}

async function generateKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: "SHA-256" }
    },
    true, ["sign", "verify"]
  );
}

async function exportPublicKey(publicKey) {
  const spki = await window.crypto.subtle.exportKey("spki", publicKey);
  const base64 = arrayBufferToBase64(spki);
  return `-----BEGIN PUBLIC KEY-----\n${formatBase64(base64)}\n-----END PUBLIC KEY-----`;
}

async function exportPrivateKey(privateKey) {
  const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", privateKey);
  const base64 = arrayBufferToBase64(pkcs8);
  return `-----BEGIN PRIVATE KEY-----\n${formatBase64(base64)}\n-----END PRIVATE KEY-----`;
}

// === UTILITIES ===
function createStatusDiv() {
  const status = document.createElement('div');
  status.id = 'login-status';
  status.style.marginTop = '20px';
  document.querySelector('.container, form').appendChild(status);
  return status;
}

function showStatus(message, type = 'info') {
  const status = document.getElementById('status') || document.getElementById('login-status');
  if (!status) return;
  
  status.innerHTML = message;
  status.className = `status-${type}`;
  
  const colors = {
    success: { bg: '#d4edda', color: '#155724', border: '#c3e6cb' },
    error: { bg: '#f8d7da', color: '#721c24', border: '#f5c6cb' },
    info: { bg: '#d1ecf1', color: '#0c5460', border: '#bee5eb' }
  };
  
  const style = colors[type] || colors.info;
  Object.assign(status.style, {
    ...style,
    padding: '15px',
    borderRadius: '4px',
    marginTop: '15px',
    border: `1px solid ${style.border}`
  });
}

function isValidPassword(password) {
  return password.length >= 8 && 
         /[A-Z]/.test(password) && 
         /\d/.test(password) && 
         /[!@#$%^&*(),.?":{}|<>]/.test(password);
}

function getErrorMessage(code) {
  const messages = {
    'invalid_credentials': 'Invalid username or password',
    'invalid_password': 'Incorrect password',
    'verification_error': 'Digital signature verification failed',
    'user_exists': 'Username already exists',
    'password_too_short': 'Password too short',
    'invalid_key_format': 'Invalid cryptographic key'
  };
  return messages[code];
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function formatBase64(base64) {
  return base64.match(/.{1,64}/g).join('\n');
}
