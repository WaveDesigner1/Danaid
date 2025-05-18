 * Admin Users - skrypt do zarządzania użytkownikami w panelu administratora
 * Wersja poprawiona uwzględniająca problemy z ładowaniem użytkowników
 */

// Inicjalizacja sesji administracyjnej
(function() {
    // Pobierz dane z sesji przy starcie
    document.addEventListener('DOMContentLoaded', function() {
        // Załaduj dane użytkownika jeśli jesteśmy zalogowani
        checkSession();
        
        // Inicjalizacja listy użytkowników
        loadUsers();

        // Obsługa kliknięcia przycisku odświeżenia użytkowników
        const refreshButton = document.getElementById('refresh-users');
        if (refreshButton) {
            refreshButton.addEventListener('click', function() {
                loadUsers();
                showNotification('Odświeżanie listy użytkowników...', 'info');
            });
        }
    });
    
    // Funkcja sprawdzająca sesję i ustawiająca ID użytkownika
    function checkSession() {
        fetch('/check_session', {
            method: 'GET',
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
        })
        .then(response => response.json())
        .then(data => {
            if (data.authenticated) {
                // Zapisz ID użytkownika w sessionStorage
                sessionStorage.setItem('user_id', data.user_id);
                sessionStorage.setItem('username', data.username);
                sessionStorage.setItem('is_admin', data.is_admin);
                console.log('Sesja poprawnie załadowana, ID użytkownika:', data.user_id);
            } else {
                console.log('Brak sesji, przekierowanie do logowania');
                window.location.href = '/';
            }
        })
        .catch(error => {
            console.error('Błąd podczas sprawdzania sesji:', error);
        });
    }
})();

/**
 * Funkcja do pobierania i wyświetlania listy użytkowników
 * Zmodyfikowana, aby najpierw próbować bezpośrednio API
 */
function loadUsers() {
    const usersTable = document.getElementById('users-table-body');
    
    if (!usersTable) {
        console.error('Nie znaleziono tabeli użytkowników');
        return;
    }
    
    // Pokaż loader
    usersTable.innerHTML = '<tr><td colspan="6" class="text-center"><i class="fa fa-spinner fa-spin"></i> Ładowanie użytkowników...</td></tr>';
    
    // Bezpośrednio używamy API /api/users jako głównego źródła danych
    fetch('/api/users?t=' + Date.now(), {
        method: 'GET',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Cache-Control': 'no-cache'
        },
        credentials: 'same-origin'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Błąd serwera: ' + response.status);
        }
        return response.json();
    })
    .then(users => {
        // Sprawdź, czy użytkownicy to tablica
        if (!Array.isArray(users)) {
            if (users.error) {
                throw new Error(users.error);
            } else {
                throw new Error('Nieprawidłowy format danych z API');
            }
        }
        
        // Sprawdź, czy dane użytkowników są poprawne
        const validUsers = users.filter(user => user && user.id !== undefined);
        
        if (validUsers.length === 0) {
            usersTable.innerHTML = '<tr><td colspan="6" class="text-center">Brak użytkowników lub nieprawidłowe dane</td></tr>';
            return;
        }
        
        // Aktualizuj statystyki
        updateStatistics(validUsers);
        
        usersTable.innerHTML = '';
        
        // Pobierz ID aktualnego użytkownika z sessionStorage
        const currentUserId = parseInt(sessionStorage.getItem('user_id'));
        
        // Wyświetl użytkowników
        validUsers.forEach(user => {
            // Upewnij się, że wszystkie pola istnieją (użyj domyślnych wartości jeśli brakuje)
            const userData = {
                id: user.id,
                username: user.username || 'Brak nazwy',
                user_id: user.user_id || user.id.toString(),
                is_online: !!user.is_online,
                is_admin: !!user.is_admin // Konwersja na boolean
            };
            
            const row = document.createElement('tr');
            row.className = 'user-row';
            row.setAttribute('data-user-id', userData.id);
            
            // Zablokuj usuwanie/zmianę własnego konta
            const isCurrentUser = currentUserId === parseInt(userData.id);
            
            row.innerHTML = `
                <td>${userData.id}</td>
                <td class="username">${userData.username}</td>
                <td>${userData.user_id}</td>
                <td>${userData.is_online ? '<span class="admin-badge success">Online</span>' : '<span class="admin-badge secondary">Offline</span>'}</td>
                <td>${userData.is_admin ? '<span class="admin-badge primary">Administrator</span>' : '<span class="admin-badge secondary">Użytkownik</span>'}</td>
                <td class="user-actions">
                    ${isCurrentUser ? '<em>Aktualny użytkownik</em>' : `
                        <button class="admin-btn ${userData.is_admin ? 'warning' : 'success'} admin-btn-sm toggle-admin-btn" data-user-id="${userData.id}" data-username="${userData.username}">
                            ${userData.is_admin ? '<i class="fa fa-times"></i> Odbierz uprawnienia' : '<i class="fa fa-check"></i> Nadaj uprawnienia'}
                        </button>
                        <button class="admin-btn danger admin-btn-sm delete-user-btn" data-user-id="${userData.id}" data-username="${userData.username}">
                            <i class="fa fa-trash"></i> Usuń
                        </button>
                    `}
                </td>
            `;
            
            usersTable.appendChild(row);
        });
        
        // Dodaj obsługę zdarzeń dla przycisków
        attachButtonHandlers();
    })
    .catch(error => {
        console.error('Błąd podczas pobierania użytkowników z API:', error);
        usersTable.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Błąd ładowania danych: ${error.message}</td></tr>`;
        showNotification('Błąd podczas pobierania użytkowników: ' + error.message, 'error');
        
        // W przypadku problemu z API, spróbuj pobrać dane z Flask-Admin jako fallback
        fallbackToFlaskAdmin(usersTable);
    });
}

/**
 * Funkcja zapasowa do pobrania użytkowników z widoku Flask-Admin
 * @param {HTMLElement} usersTable - Element tabeli użytkowników
 */
function fallbackToFlaskAdmin(usersTable) {
    console.log('Próba pobrania użytkowników z zapasowego źródła (Flask-Admin)...');
    
    // Pobierz dane z panelu Flask-Admin
    fetch('/flask_admin/user/?t=' + Date.now(), {
        method: 'GET',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Cache-Control': 'no-cache'
        },
        credentials: 'same-origin'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Błąd serwera: ' + response.status);
        }
        return response.text(); // Pobieramy jako tekst, bo strona Flask-Admin zwraca HTML
    })
    .then(htmlContent => {
        // Parsowanie zawartości HTML
        const parser = new DOMParser();
        const doc = parser.parseFromString(htmlContent, 'text/html');
        
        // Próba ekstrahowania danych użytkowników z tabeli Flask-Admin
        const userRows = Array.from(doc.querySelectorAll('table tbody tr'));
        
        // Jeśli nie ma wierszy, zwróć pustą tablicę
        if (!userRows || userRows.length === 0) {
            usersTable.innerHTML = '<tr><td colspan="6" class="text-center">Brak użytkowników</td></tr>';
            return;
        }
        
        // Parsowanie wierszy do obiektów użytkowników
        const users = userRows.map(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length < 3) return null; // Sprawdź czy ma wystarczająco komórek
            
            // Mapowanie komórek na dane użytkownika (dopasowane do układu HTML Flask-Admin)
            // Próbujemy znaleźć potrzebne dane w różnych komórkach tabeli
            
            // ID - pierwsza kolumna
            const id = cells[0] ? cells[0].textContent.trim() : '';
            
            // Nazwa użytkownika - szukamy w kilku miejscach
            let username = '';
            for (let i = 0; i < cells.length; i++) {
                const text = cells[i].textContent.trim();
                // Jeśli znajdziemy komórkę zawierającą nazwę użytkownika (nie numeryczną)
                if (text && text.length > 0 && isNaN(text) && text !== 'False' && text !== 'True') {
                    username = text;
                    break;
                }
            }
            
            // User_ID - używamy ID jako fallback
            const user_id = id;
            
            // Admin - szukamy w komórkach tekstu "True" lub "False"
            let is_admin = false;
            for (let i = 0; i < cells.length; i++) {
                const text = cells[i].textContent.trim();
                if (text === 'True') {
                    is_admin = true;
                    break;
                }
            }
            
            // Status Online - zawsze false, bo Flask-Admin tego nie pokazuje
            const is_online = false;
            
            return { id, username, user_id, is_admin, is_online };
        }).filter(user => user !== null && user.id && user.username); // Usuń niepoprawne wpisy
        
        // Aktualizuj statystyki
        updateStatistics(users);
        
        // Jeśli nie znaleziono użytkowników po filtrowaniu
        if (users.length === 0) {
            usersTable.innerHTML = '<tr><td colspan="6" class="text-center">Nie znaleziono prawidłowych danych użytkowników</td></tr>';
            return;
        }
        
        usersTable.innerHTML = '';
        
        // Pobierz ID aktualnego użytkownika z sessionStorage
        const currentUserId = parseInt(sessionStorage.getItem('user_id'));
        
        // Wyświetl użytkowników
        users.forEach(user => {
            const row = document.createElement('tr');
            row.className = 'user-row';
            row.setAttribute('data-user-id', user.id);
            
            // Zablokuj usuwanie/zmianę własnego konta
            const isCurrentUser = currentUserId === parseInt(user.id);
            
            row.innerHTML = `
                <td>${user.id}</td>
                <td class="username">${user.username}</td>
                <td>${user.user_id}</td>
                <td>${user.is_online ? '<span class="admin-badge success">Online</span>' : '<span class=
