/**
 * user_script.js - NAPRAWIONY dla UnifiedCrypto
 * Obsługa logowania z podpisem cyfrowym
 */
document.addEventListener('DOMContentLoaded', function () {
  const loginForm = document.getElementById("login-form");
  const loginButton = document.getElementById("login-button");
  
  console.log("✅ User script załadowany");
  
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

    // Walidacja podstawowa
    if (!username || !password) {
      statusDiv.textContent = "Wypełnij wszystkie pola";
      return;
    }

    if (!pemFileInput || !pemFileInput.files || !pemFileInput.files[0]) {
      statusDiv.textContent = "Wybierz plik klucza prywatnego (.pem)";
      return;
    }

    try {
      const file = pemFileInput.files[0];
      const privateKeyPEM = await file.text();
      
      console.log("🔑 Ładowanie klucza prywatnego...");
      
      // NAPRAWIONE: Zachowaj klucz prywatny w localStorage dla UnifiedCrypto
      sessionStorage.setItem('private_key_pem', privateKeyPEM);
      
      // NAPRAWIONE: Sprawdź czy UnifiedCrypto jest dostępny
      // (w logowaniu nie potrzebujemy UnifiedCrypto bo to jest przed załadowaniem chat.html)
      // Używamy bezpośrednio Web Crypto API jak wcześniej
      
      // Importuj klucz prywatny do podpisywania (RSASSA-PKCS1-v1_5)
      const privateKey = await importPrivateKeyForSigning(privateKeyPEM);
      
      // Podpisz hasło kluczem prywatnym
      const signature = await signWithPrivateKey(privateKey, password);
      
      console.log("✅ Klucz załadowany i podpis utworzony");
      
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
        throw new Error(`Błąd HTTP: ${response.status}`);
      }

      const result = await response.json();

      if (result.status === 'success') {
        console.log("✅ Logowanie pomyślne");
        
        // Zapisz dane sesji
        sessionStorage.setItem('user_id', result.user_id);
        sessionStorage.setItem('username', username);
        sessionStorage.setItem('is_admin', result.is_admin);
        sessionStorage.setItem('isLoggedIn', 'true');
        
        // Także w localStorage jako backup
        localStorage.setItem('isLoggedIn', 'true');
        
        statusDiv.innerHTML = `✅ Zalogowano pomyślnie! Za chwilę nastąpi przekierowanie...`;
        statusDiv.style.color = '#4CAF50';
        
        // Przekierowanie po krótkim opóźnieniu
        setTimeout(() => {
          window.location.href = '/chat';
        }, 1500);
      } else {
        // Obsługa błędów z serwera
        let errorMessage = 'Błąd logowania';
        
        switch(result.code) {
          case 'invalid_credentials':
            errorMessage = 'Niepoprawne dane logowania';
            break;
          case 'invalid_password':
            errorMessage = 'Niepoprawne hasło';
            break;
          case 'verification_error':
            errorMessage = 'Błąd weryfikacji podpisu - sprawdź klucz prywatny';
            break;
          default:
            errorMessage = result.message || 'Nieznany błąd logowania';
        }
        
        statusDiv.textContent = errorMessage;
        statusDiv.style.color = '#F44336';
      }
    } catch (error) {
      console.error("❌ Błąd logowania:", error);
      
      let errorMessage = "Błąd logowania";
      if (error.message.includes('key')) {
        errorMessage = "Nieprawidłowy plik klucza prywatnego";
      } else if (error.message.includes('network') || error.message.includes('fetch')) {
        errorMessage = "Błąd połączenia z serwerem";
      } else {
        errorMessage = "Wystąpił nieoczekiwany błąd: " + error.message;
      }
      
      statusDiv.textContent = errorMessage;
      statusDiv.style.color = '#F44336';
    }
  }

  /**
   * NAPRAWIONE: Import klucza prywatnego do podpisywania (RSASSA-PKCS1-v1_5)
   * Używa RSASSA zamiast RSA-OAEP bo to jest do podpisywania, nie szyfrowania
   */
  async function importPrivateKeyForSigning(pem) {
    try {
      const pemContents = pem
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace(/\s+/g, "");

      const binaryDer = str2ab(atob(pemContents));

      return await window.crypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        {
          name: "RSASSA-PKCS1-v1_5",  // Do podpisywania
          hash: "SHA-256"
        },
        false,
        ["sign"]  // Tylko do podpisywania
      );
    } catch (error) {
      console.error("❌ Błąd importu klucza do podpisywania:", error);
      throw new Error("Nie można załadować klucza prywatnego do podpisywania");
    }
  }

  /**
   * Podpisywanie hasła kluczem prywatnym
   */
  async function signWithPrivateKey(privateKey, data) {
    try {
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
    } catch (error) {
      console.error("❌ Błąd podpisywania:", error);
      throw new Error("Nie można utworzyć podpisu cyfrowego");
    }
  }

  /**
   * Funkcje pomocnicze - bez zmian
   */
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
  
  console.log("✅ User script gotowy do logowania");
});
