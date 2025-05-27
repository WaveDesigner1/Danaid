document.addEventListener('DOMContentLoaded', function () {
  const loginForm = document.getElementById("login-form");
  const loginButton = document.getElementById("login-button");
  
  if (loginForm) {
    loginForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      await handleLogin();
    });
    
    if (loginButton) {
      loginButton.addEventListener("click", async function() {
        await handleLogin();
      });
    }
  }
  
  async function handleLogin() {
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;
    const pemFileInput = document.getElementById("pem-file");
    let statusDiv = document.getElementById("login-status");

    if (!statusDiv) {
      statusDiv = document.createElement("div");
      statusDiv.id = "login-status";
      loginForm.appendChild(statusDiv);
    }

    statusDiv.style.display = "block";
    statusDiv.textContent = "Logowanie...";

    if (!pemFileInput || !pemFileInput.files || !pemFileInput.files[0]) {
      statusDiv.textContent = "Wybierz plik klucza prywatnego (.pem)";
      return;
    }

    try {
      const file = pemFileInput.files[0];
      const privateKeyPEM = await file.text();
      
      // Zachowaj klucz prywatny w localStorage
      localStorage.setItem('private_key_pem', privateKeyPEM);
      
      // Importuj klucz prywatny
      const privateKey = await importPrivateKeyFromPEM(privateKeyPEM);
      
      // Podpisz hasło kluczem prywatnym
      const signature = await signWithPrivateKey(privateKey, password);
      
      // Wyślij dane logowania
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: username,
          password: password,
          signature: signature
        }),
        credentials: 'same-origin'
      });

      if (!response.ok) {
        statusDiv.textContent = `Błąd logowania: ${response.status}`;
        return;
      }

      const result = await response.json();

      if (result.status === 'success') {
        // Zapisz dane sesji
        sessionStorage.setItem('user_id', result.user_id);
        sessionStorage.setItem('username', username);
        sessionStorage.setItem('is_admin', result.is_admin);
        sessionStorage.setItem('isLoggedIn', 'true');
        
        statusDiv.innerHTML = `Zalogowano pomyślnie! Za chwilę nastąpi przekierowanie...`;
        
        // Przekierowanie po krótkim opóźnieniu
        setTimeout(() => {
          window.location.href = '/chat';
        }, 1500);
      } else {
        statusDiv.textContent = result.message || 'Błąd logowania';
      }
    } catch (error) {
      statusDiv.textContent = "Nieprawidłowy plik klucza lub błąd serwera";
      console.error("Błąd logowania:", error);
    }
  }

  async function importPrivateKeyFromPEM(pem) {
    const pemContents = pem
      .replace("-----BEGIN PRIVATE KEY-----", "")
      .replace("-----END PRIVATE KEY-----", "")
      .replace(/\s+/g, "");

    const binaryDer = str2ab(atob(pemContents));

    return await window.crypto.subtle.importKey(
      "pkcs8",
      binaryDer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    );
  }

  async function signWithPrivateKey(privateKey, data) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    
    const signature = await window.crypto.subtle.sign(
      {
        name: "RSASSA-PKCS1-v1_5"
      },
      privateKey,
      dataBuffer
    );
    
    return arrayBufferToBase64(signature);
  }

  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }
});
