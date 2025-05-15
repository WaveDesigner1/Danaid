/**
 * Session Manager - zarządzanie sesją użytkownika
 */
class SessionManager {
    constructor() {
        this.isLoggedIn = sessionStorage.getItem('isLoggedIn') === 'true';
        this.isAdmin = sessionStorage.getItem('is_admin') === 'true';
        
        // Czas wygaśnięcia sesji (30 minut)
        this.sessionTimeout = 30 * 60 * 1000;
        
        // Nasłuchuj na zamknięcie przeglądarki/karty
        window.addEventListener('beforeunload', this.handleTabClose.bind(this));
        
        // Regularnie sprawdzaj czas sesji (co minutę)
        this.checkSessionInterval = setInterval(this.checkSessionTimeout.bind(this), 60 * 1000);
        
        // Sprawdź sesję na serwerze przy inicjalizacji
        this.checkServerSession();
    }
    
    // Sprawdzanie stanu sesji na serwerze
    async checkServerSession() {
        try {
            const response = await fetch('/api/check_session', {
                method: 'GET',
                credentials: 'same-origin'
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.authenticated) {
                    this.isLoggedIn = true;
                    this.isAdmin = data.is_admin;
                    
                    // Aktualizuj sessionStorage
                    sessionStorage.setItem('isLoggedIn', 'true');
                    sessionStorage.setItem('is_admin', this.isAdmin.toString());
                    sessionStorage.setItem('user_id', data.user_id);
                    sessionStorage.setItem('username', data.username);
                    sessionStorage.setItem('sessionStartTime', Date.now().toString());
                    
                    return true;
                }
            }
            
            // Jeśli nie zalogowany lub błąd, wyczyść dane sesji
            this.clearSessionData();
            this.isLoggedIn = false;
            this.isAdmin = false;
            
            return false;
        } catch (error) {
            console.error('Błąd podczas sprawdzania sesji:', error);
            this.clearSessionData();
            this.isLoggedIn = false;
            this.isAdmin = false;
            
            return false;
        }
    }
    
    // Rejestracja logowania
    login(userData = {}) {
        this.isLoggedIn = true;
        this.isAdmin = userData.is_admin === true;
        
        // Zapisanie w sessionStorage
        sessionStorage.setItem('isLoggedIn', 'true');
        sessionStorage.setItem('sessionStartTime', Date.now().toString());
        sessionStorage.setItem('is_admin', this.isAdmin.toString());
        sessionStorage.setItem('user_id', userData.user_id);
        sessionStorage.setItem('username', userData.username);
    }
    
    // Wylogowanie
    logout() {
        this.isLoggedIn = false;
        this.isAdmin = false;
        
        // Czyszczenie sessionStorage
        this.clearSessionData();
        
        // Wyślij żądanie do serwera o wylogowanie
        fetch('/logout', {
            method: 'GET',
            credentials: 'same-origin'
        }).then(() => {
            // Przekieruj do strony logowania
            window.location.href = '/';
        }).catch(error => {
            console.error('Błąd podczas wylogowania:', error);
            // Przekieruj do strony logowania nawet w przypadku błędu
            window.location.href = '/';
        });
    }
    
    // Czyszczenie danych sesji
    clearSessionData() {
        sessionStorage.removeItem('isLoggedIn');
        sessionStorage.removeItem('sessionStartTime');
        sessionStorage.removeItem('is_admin');
        sessionStorage.removeItem('user_id');
        sessionStorage.removeItem('username');
    }
    
    // Sprawdź, czy sesja wygasła
    checkSessionTimeout() {
        if (!this.isLoggedIn) return;
        
        const currentTime = Date.now();
        const sessionStartTime = parseInt(sessionStorage.getItem('sessionStartTime') || '0');
        const sessionAge = currentTime - sessionStartTime;
        
        if (sessionAge > this.sessionTimeout) {
            console.log('Sesja wygasła - automatyczne wylogowanie');
            this.logout();
        }
    }
    
    // Obsługa zamknięcia karty
    handleTabClose() {
        if (this.isLoggedIn) {
            // Metoda sendBeacon jest preferowana, ponieważ działa nawet przy zamykaniu przeglądarki
            navigator.sendBeacon('/api/logout');
            this.clearSessionData();
        }
    }
    
    // Odnowienie sesji (po aktywności użytkownika)
    refreshActivity() {
        if (this.isLoggedIn) {
            sessionStorage.setItem('sessionStartTime', Date.now().toString());
        }
    }
    
    // Sprawdzenie czy użytkownik jest adminem
    isUserAdmin() {
        return this.isAdmin === true;
    }
}

// Inicjalizacja menedżera sesji
const sessionManager = new SessionManager();

// Nasłuchuj na aktywność użytkownika, aby odświeżać sesję
['click', 'mousedown', 'keypress', 'touchstart', 'scroll'].forEach(eventType => {
    document.addEventListener(eventType, () => {
        sessionManager.refreshActivity();
    }, { passive: true });
});

// Eksportuj do globalnego scope
window.sessionManager = sessionManager;
