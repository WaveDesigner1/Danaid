/**
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
 */
function loadUsers() {
    const usersTable = document.getElementById('users-table-body');
    
    if (!usersTable) {
        console.error('Nie znaleziono tabeli użytkowników');
        return;
    }
    
    // Pokaż loader
    usersTable.innerHTML = '<tr><td colspan="6" class="text-center"><i class="fa fa-spinner fa-spin"></i> Ładowanie użytkowników...</td></tr>';
    
    // Pobierz dane z panelu Flask-Admin, dodaj parametr timestamp, aby uniknąć cachowania
    fetch('https://danaid.up.railway.app/flask_admin/user/?t=' + Date.now(), {
        method: 'GET',
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
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
        const userRows = Array.from(doc.querySelectorAll('table.table tbody tr'));
        
        // Jeśli nie ma wierszy, zwróć pustą tablicę
        if (!userRows || userRows.length === 0) {
            usersTable.innerHTML = '<tr><td colspan="6" class="text-center">Brak użytkowników</td></tr>';
            return;
        }
        
        // Parsowanie wierszy do obiektów użytkowników
        const users = userRows.map(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length < 4) return null; // Sprawdź czy ma wystarczająco komórek
            
            // ID to zazwyczaj pierwsza kolumna
            const id = cells[0].textContent.trim();
            
            // Próba uzyskania nazwy użytkownika - może być w różnych kolumnach
            const username = cells[1] ? cells[1].textContent.trim() : 'Nieznany';
            
            // Spróbuj znaleźć user_id w danych
            const user_id = cells[2] ? cells[2].textContent.trim() : id;
            
            // Sprawdź, czy jest administratorem (może być kolumna z wartością true/false)
            const is_admin = (cells[3] && cells[3].textContent.toLowerCase().includes('true')) || false;
            
            // Sprawdź status online (może nie być dostępny w Flask-Admin)
            const is_online = false; // Domyślnie ustaw na false, bo Flask-Admin może nie mieć tej informacji
            
            return { id, username, user_id, is_admin, is_online };
        }).filter(user => user !== null); // Usuń niepoprawne wpisy
        
        // Aktualizuj statystyki
        updateStatistics(users);
        
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
                <td>${user.is_online ? '<span class="label label-success">Online</span>' : '<span class="label label-default">Offline</span>'}</td>
                <td>${user.is_admin ? '<span class="label label-primary">Administrator</span>' : '<span class="label label-default">Użytkownik</span>'}</td>
                <td class="user-actions">
                    ${isCurrentUser ? '<em class="text-muted">Aktualny użytkownik</em>' : `
                        <button class="btn btn-sm ${user.is_admin ? 'btn-warning' : 'btn-success'} toggle-admin-btn" data-user-id="${user.id}" data-username="${user.username}">
                            ${user.is_admin ? '<i class="fa fa-times"></i> Odbierz uprawnienia' : '<i class="fa fa-check"></i> Nadaj uprawnienia'}
                        </button>
                        <button class="btn btn-sm btn-danger delete-user-btn" data-user-id="${user.id}" data-username="${user.username}">
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
        console.error('Błąd podczas pobierania użytkowników:', error);
        usersTable.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Błąd ładowania danych: ${error.message}</td></tr>`;
        showNotification('Błąd podczas pobierania użytkowników: ' + error.message, 'error');
        
        // W przypadku problemu z parsowaniem HTML, spróbuj pobrać dane z tradycyjnego API
        fallbackToApiUsers(usersTable);
    });
}

/**
 * Funkcja zapasowa do pobrania użytkowników z pierwotnego API
 * @param {HTMLElement} usersTable - Element tabeli użytkowników
 */
// Funkcja zapasowa do pobrania użytkowników z pierwotnego API
function fallbackToApiUsers(usersTable) {
    console.log('Próba pobrania użytkowników z zapasowego API...');
    
    fetch('/api/users?t=' + Date.now(), {
        method: 'GET',
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
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
        // Aktualizuj statystyki
        updateStatistics(users);
        
        usersTable.innerHTML = '';
        
        if (!users || users.length === 0) {
            usersTable.innerHTML = '<tr><td colspan="6" class="text-center">Brak użytkowników</td></tr>';
            return;
        }
        
        // Jeśli mamy informację o błędzie
        if (users.error) {
            usersTable.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Błąd: ${users.error}</td></tr>`;
            return;
        }
        
        // Pobierz ID aktualnego użytkownika z sessionStorage
        const currentUserId = parseInt(sessionStorage.getItem('user_id'));
        
        // Wyświetl użytkowników
        users.forEach(user => {
            const row = document.createElement('tr');
            row.className = 'user-row';
            row.setAttribute('data-user-id', user.id);
            
            // Zablokuj usuwanie/zmianę własnego konta
            const isCurrentUser = currentUserId === user.id;
            
            row.innerHTML = `
                <td>${user.id}</td>
                <td class="username">${user.username}</td>
                <td>${user.user_id}</td>
                <td>${user.is_online ? '<span class="label label-success">Online</span>' : '<span class="label label-default">Offline</span>'}</td>
                <td>${user.is_admin ? '<span class="label label-primary">Administrator</span>' : '<span class="label label-default">Użytkownik</span>'}</td>
                <td class="user-actions">
                    ${isCurrentUser ? '<em class="text-muted">Aktualny użytkownik</em>' : `
                        <button class="btn btn-sm ${user.is_admin ? 'btn-warning' : 'btn-success'} toggle-admin-btn" data-user-id="${user.id}" data-username="${user.username}">
                            ${user.is_admin ? '<i class="fa fa-times"></i> Odbierz uprawnienia' : '<i class="fa fa-check"></i> Nadaj uprawnienia'}
                        </button>
                        <button class="btn btn-sm btn-danger delete-user-btn" data-user-id="${user.id}" data-username="${user.username}">
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
        console.error('Błąd podczas pobierania użytkowników z zapasowego API:', error);
        usersTable.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Błąd ładowania danych z zapasowego API: ${error.message}</td></tr>`;
        showNotification('Błąd podczas pobierania użytkowników: ' + error.message, 'error');
    });
}
function updateStatistics(users) {
    if (!users) return;
    
    // Aktualizuj licznik użytkowników
    const usersCount = document.getElementById('users-count');
    if (usersCount) {
        usersCount.textContent = users.length;
    }
    
    // Aktualizuj licznik użytkowników online
    const onlineCount = document.getElementById('online-count');
    if (onlineCount) {
        const onlineUsers = users.filter(user => user.is_online).length;
        onlineCount.textContent = onlineUsers;
    }
}

/**
 * Dodaje obsługę zdarzeń do przycisków w tabeli
 */
function attachButtonHandlers() {
    // Przyciski zmieniające uprawnienia administratora
    document.querySelectorAll('.toggle-admin-btn').forEach(button => {
        button.addEventListener('click', function() {
            const userId = this.getAttribute('data-user-id');
            const username = this.getAttribute('data-username');
            
            toggleAdmin(userId, username);
        });
    });
    
    // Przyciski usuwające użytkownika
    document.querySelectorAll('.delete-user-btn').forEach(button => {
        button.addEventListener('click', function() {
            const userId = this.getAttribute('data-user-id');
            const username = this.getAttribute('data-username');
            
            deleteUser(userId, username);
        });
    });
}

/**
 * Funkcja do zmiany uprawnień administratora
 * @param {number} userId - ID użytkownika
 * @param {string} username - Nazwa użytkownika
 */
function toggleAdmin(userId, username) {
    if (confirm(`Czy na pewno chcesz zmienić uprawnienia administratora dla użytkownika ${username}?`)) {
        fetch(`/api/users/${userId}/toggle_admin`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Błąd serwera: ' + response.status);
            }
            return response.json();
        })
        .then(data => {
            if (data.status === 'success') {
                showNotification(data.message, 'success');
                loadUsers(); // Odśwież listę użytkowników
            } else {
                showNotification(`Błąd: ${data.message}`, 'error');
            }
        })
        .catch(error => {
            console.error('Błąd podczas zmiany uprawnień:', error);
            showNotification('Wystąpił błąd podczas zmiany uprawnień: ' + error.message, 'error');
        });
    }
}

/**
 * Funkcja do usuwania użytkownika
 * @param {number} userId - ID użytkownika
 * @param {string} username - Nazwa użytkownika
 */
function deleteUser(userId, username) {
    if (confirm(`Czy na pewno chcesz usunąć użytkownika ${username}? To działanie jest nieodwracalne i usunie wszystkie powiązane dane, w tym sesje czatu i wiadomości.`)) {
        fetch(`/api/users/${userId}/delete`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Błąd serwera: ' + response.status);
            }
            return response.json();
        })
        .then(data => {
            if (data.status === 'success') {
                showNotification(data.message, 'success');
                loadUsers(); // Odśwież listę użytkowników
            } else {
                showNotification(`Błąd: ${data.message}`, 'error');
            }
        })
        .catch(error => {
            console.error('Błąd podczas usuwania użytkownika:', error);
            showNotification('Wystąpił błąd podczas usuwania użytkownika: ' + error.message, 'error');
        });
    }
}

/**
 * Funkcja do wyświetlania powiadomień
 * @param {string} message - Treść powiadomienia
 * @param {string} type - Typ powiadomienia (success, error, info, warning)
 */
function showNotification(message, type = 'info') {
    // Mapowanie typów na klasy Bootstrap
    const typeClass = {
        'success': 'alert-success',
        'error': 'alert-danger',
        'info': 'alert-info',
        'warning': 'alert-warning'
    };
    
    // Domyślny typ, jeśli podany jest nieprawidłowy
    const alertClass = typeClass[type] || 'alert-info';
    
    // Sprawdź, czy kontener powiadomień istnieje
    let notificationsContainer = document.getElementById('notifications-container');
    
    if (!notificationsContainer) {
        // Utwórz kontener, jeśli nie istnieje
        notificationsContainer = document.createElement('div');
        notificationsContainer.id = 'notifications-container';
        notificationsContainer.style.position = 'fixed';
        notificationsContainer.style.top = '20px';
        notificationsContainer.style.right = '20px';
        notificationsContainer.style.zIndex = '9999';
        document.body.appendChild(notificationsContainer);
    }
    
    // Utwórz powiadomienie
    const notification = document.createElement('div');
    notification.className = `alert ${alertClass}`;
    notification.style.minWidth = '300px';
    notification.style.marginBottom = '10px';
    notification.style.boxShadow = '0 4px 8px rgba(0,0,0,0.2)';
    notification.innerHTML = `
        <button type="button" class="close" data-dismiss="alert">&times;</button>
        <div>
            <i class="fa fa-${type === 'error' ? 'exclamation-circle' : 
                         type === 'success' ? 'check-circle' : 
                         type === 'warning' ? 'exclamation-triangle' : 'info-circle'}"></i>
            ${message}
        </div>
    `;
    
    // Dodaj powiadomienie do kontenera
    notificationsContainer.appendChild(notification);
    
    // Automatycznie zamknij po 5 sekundach
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transition = 'opacity 0.5s';
        setTimeout(() => {
            if (notification.parentNode === notificationsContainer) {
                notificationsContainer.removeChild(notification);
            }
        }, 500);
    }, 5000);
    
    // Obsługa przycisku zamknięcia
    const closeButton = notification.querySelector('.close');
    closeButton.addEventListener('click', function() {
        notification.remove();
    });
}
