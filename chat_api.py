// session_manager.js - zarządzanie sesją użytkownika

/**
 * Klasa zarządzająca sesją użytkownika
 */
class SessionManager {
    constructor() {
        this.isLoggedIn = false;
        this.userData = null;
    }

    /**
     * Sprawdza status sesji na serwerze
     * @returns {Promise<boolean>} - true jeśli użytkownik jest zalogowany
     */
    async checkServerSession() {
        try {
            const response = await fetch('/check_session');
            const data = await response.json();
            
            if (data.authenticated) {
                this.isLoggedIn = true;
                this.userData = {
                    id: data.user_id,
                    username: data.username,
                    isAdmin: data.is_admin,
                    isOnline: data.is_online
                };
                return true;
            } else {
                this.isLoggedIn = false;
                this.userData = null;
                return false;
            }
        } catch (error) {
            console.error('Błąd sprawdzania sesji:', error);
            this.isLoggedIn = false;
            this.userData = null;
            return false;
        }
    }

    /**
     * Loguje użytkownika
     * @param {string} username - nazwa użytkownika
     * @param {string} password - hasło
     * @param {string} privateKey - klucz prywatny w formacie PEM
     * @returns {Promise<Object>} - wynik logowania
     */
    async login(username, password, privateKey) {
        try {
            // Generuj podpis z hasła używając klucza prywatnego
            const signature = await this.generateSignature(password, privateKey);
            
            // Wysyłanie danych logowania
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username,
                    password: password,
                    signature: signature
                })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.isLoggedIn = true;
                this.userData = {
                    username: username,
                    userId: data.user_id,
                    isAdmin: data.is_admin
                };
                return { success: true, message: 'Zalogowano pomyślnie' };
            } else {
                this.isLoggedIn = false;
                return { success: false, message: this.getErrorMessage(data.code) };
            }
        } catch (error) {
            console.error('Błąd logowania:', error);
            return { success: false, message: 'Błąd podczas logowania: ' + error.message };
        }
    }

    /**
     * Generuje podpis cyfrowy
     * @param {string} data - dane do podpisania
     * @param {string} privateKeyPEM - klucz prywatny PEM
     * @returns {Promise<string>} - podpis w formacie base64
     */
    async generateSignature(data, privateKeyPEM) {
        // W prawdziwej implementacji tutaj byłoby generowanie podpisu
        // Używając biblioteki kryptograficznej (np. crypto-js, forge, itp.)
        
        // Przykładowa implementacja zastępcza
        return btoa('placeholder_signature');
    }

    /**
     * Wylogowuje użytkownika
     * @returns {Promise<boolean>} - true jeśli wylogowano pomyślnie
     */
    async logout() {
        try {
            await fetch('/logout');
            this.isLoggedIn = false;
            this.userData = null;
            return true;
        } catch (error) {
            console.error('Błąd wylogowywania:', error);
            // Mimo błędu, czyścimy dane sesji lokalnie
            this.isLoggedIn = false;
            this.userData = null;
            return false;
        }
    }

    /**
     * Wylogowuje użytkownika w trybie cichym (np. przy zamknięciu karty)
     */
    silentLogout() {
        try {
            fetch('/silent-logout', { method: 'POST' });
            this.isLoggedIn = false;
            this.userData = null;
        } catch (error) {
            console.error('Błąd cichego wylogowywania:', error);
            this.isLoggedIn = false;
            this.userData = null;
        }
    }

    /**
     * Przekierowuje do wylogowania awaryjnego
     */
    forceLogout() {
        window.location.href = '/force-logout';
    }

    /**
     * Sprawdza czy użytkownik jest zalogowany
     * @returns {boolean} - status zalogowania
     */
    isAuthenticated() {
        return this.isLoggedIn;
    }

    /**
     * Pobiera dane zalogowanego użytkownika
     * @returns {Object|null} - dane użytkownika lub null jeśli niezalogowany
     */
    getUserData() {
        return this.userData;
    }

    /**
     * Zwraca przyjazny komunikat błędu na podstawie kodu
     * @param {string} errorCode - kod błędu z API
     * @returns {string} - komunikat błędu
     */
    getErrorMessage(errorCode) {
        const errorMessages = {
            'missing_data': 'Brak wymaganych danych',
            'invalid_credentials': 'Nieprawidłowa nazwa użytkownika lub hasło',
            'invalid_password': 'Nieprawidłowe hasło',
            'missing_signature': 'Brak podpisu cyfrowego',
            'verification_error': 'Błąd weryfikacji podpisu',
            'server_error': 'Błąd serwera'
        };
        
        return errorMessages[errorCode] || 'Nieznany błąd';
    }
}

// Inicjalizacja menedżera sesji jako globalny obiekt
window.sessionManager = new window.sessionManager || new SessionManager();
