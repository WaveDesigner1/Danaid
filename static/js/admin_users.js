/**
 * Admin Users - skrypt do zarządzania użytkownikami w panelu administratora
 * Wersja dostosowana do korzystania z user_id
 */

// Inicjalizacja sesji administracyjnej
document.addEventListener('DOMContentLoaded', function() {
    console.log("Admin users.js loaded");
    
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
    
    // Sprawdź sesję i ustaw ID użytkownika
    checkSession();
});

// Funkcja sprawdzająca sesję i ustawiająca ID użytkownika
function checkSession() {
    fetch('/check_session', {
        method: 'GET',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        },
        credentials: 'same-origin'
    })
    .then(response => {
        console.log("Odpowiedź sesji status:", response.status);
        if (!response.ok) {
            throw new Error('Status: ' + response.status);
        }
        return response.json();
    })
    .then(data => {
        console.log("Dane sesji:", data);
        if (data.authenticated) {
            // Zapisz ID użytkownika w sessionStorage
            sessionStorage.setItem('current_user_id', data.user_id);
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
        showNotification('Błąd sesji: ' + error.message, 'error');
    });
}

/**
 * Funkcja do pobierania i wyświetlania listy użytkowników
 */
function loadUsers() {
    console.log("Loading users...");
    
    const usersTable = document.getElementById('users-table-body');
    
    if (!usersTable) {
        console.error('Nie znaleziono tabeli użytkowników');
        return;
    }
    
    // Pokaż loader
    usersTable.innerHTML = '<tr><td colspan="6" class="text-center"><i class="fa fa-spinner fa-spin"></i> Ładowanie użytkowników...</td></tr>';
    
    // Dodaj timestamp do URL, aby uniknąć cachowania
    fetch('/api/users?' + new Date().getTime(), {
        method: 'GET',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        },
        credentials: 'same-origin'
    })
    .then(response => {
        console.log("Odpowiedź API status:", response.status);
        if (!response.ok) {
            throw new Error('Status: ' + response.status);
        }
        return response.json().catch(error => {
            console.error("Błąd parsowania JSON:", error);
            throw new Error('Problem z formatem danych: ' + error.message);
        });
    })
    .then(result => {
        console.log("Received data:", result);
        
        // Sprawdź, czy mamy właściwy format odpowiedzi
        if (result.status === 'error') {
            throw new Error(result.message || 'Nieznany błąd API');
        }
        
        if (result.status !== 'success' || !result.users) {
            throw new Error('Nieprawidłowy format danych z API: ' + JSON.stringify(result));
        }
        
        const users = result.users;
        
        // Jeśli lista jest pusta
        if (users.length === 0) {
            usersTable.innerHTML = '<tr><td colspan="6" class="text-center">Brak użytkowników</td></tr>';
            return;
        }
        
        // Wyczyść tabelę
        usersTable.innerHTML = '';
        
        // Pobierz ID aktualnego użytkownika z sessionStorage
        const currentUserId = sessionStorage.getItem('current_user_id');
        console.log("Aktualny user_id:", currentUserId);
        
        // Wyświetl użytkowników
        users.forEach(user => {
            // Upewnij się, że wszystkie pola istnieją (użyj domyślnych wartości jeśli brakuje)
            const userData = {
                id: user.id || 0,
                username: user.username || 'Brak nazwy',
                user_id: user.user_id || (user.id ? user.id.toString() : '0'),
                is_online: Boolean(user.is_online),
                is_admin: Boolean(user.is_admin)
            };
            
            // Sprawdź, czy to aktualny użytkownik
            const isCurrentUser = currentUserId === userData.user_id;
            
            const row = document.createElement('tr');
            row.className = 'user-row';
            row.setAttribute('data-user-id', userData.user_id); // używamy user_id jako identyfikatora
            
            row.innerHTML = `
                <td>${userData.id}</td>
                <td class="username">${userData.username}</td>
                <td>${userData.user_id}</td>
                <td>${userData.is_online ? 
                    '<span class="admin-badge success">Online</span>' : 
                    '<span class="admin-badge secondary">Offline</span>'}
                </td>
                <td>${userData.is_admin ? 
                    '<span class="admin-badge primary">Administrator</span>' : 
                    '<span class="admin-badge secondary">Użytkownik</span>'}
                </td>
                <td class="user-actions">
                    ${isCurrentUser ? 
                    '<em>Aktualny użytkownik</em>' : 
                    `<button class="admin-btn ${userData.is_admin ? 'warning' : 'success'} admin-btn-sm toggle-admin-btn" data-user-id="${userData.user_id}" data-username="${userData.username}">
                        ${userData.is_admin ? '<i class="fa fa-times"></i> Odbierz uprawnienia' : '<i class="fa fa-check"></i> Nadaj uprawnienia'}
                     </button>
                     <button class="admin-btn danger admin-btn-sm delete-user-btn" data-user-id="${userData.user_id}" data-username="${userData.username}">
                        <i class="fa fa-trash"></i> Usuń
                     </button>`}
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
    });
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
 * @param {string} userId - ID użytkownika (user_id)
 * @param {string} username - Nazwa użytkownika
 */
function toggleAdmin(userId, username) {
    if (!userId) {
        console.error('Brak ID użytkownika');
        showNotification('Błąd: Brak ID użytkownika', 'error');
        return;
    }
    
    if (confirm(`Czy na pewno chcesz zmienić uprawnienia administratora dla użytkownika "${username}"?`)) {
        fetch(`/api/users/${userId}/toggle_admin`, {
            method: 'POST',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache, no-store, must-revalidate'
            },
            credentials: 'same-origin'
        })
        .then(response => {
            console.log("Odpowiedź toggle admin status:", response.status);
            if (!response.ok) {
                throw new Error('Status: ' + response.status);
            }
            return response.json();
        })
        .then(data => {
            console.log("Odpowiedź toggle admin:", data);
            if (data.status === 'success') {
                showNotification(data.message, 'success');
                loadUsers(); // Odśwież listę użytkowników
            } else {
                showNotification(`Błąd: ${data.message || 'Nieznany błąd'}`, 'error');
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
 * @param {string} userId - ID użytkownika (user_id)
 * @param {string} username - Nazwa użytkownika
 */
function deleteUser(userId, username) {
    if (!userId) {
        console.error('Brak ID użytkownika');
        showNotification('Błąd: Brak ID użytkownika', 'error');
        return;
    }
    
    if (confirm(`Czy na pewno chcesz usunąć użytkownika "${username}"? To działanie jest nieodwracalne i usunie wszystkie powiązane dane, w tym sesje czatu i wiadomości.`)) {
        fetch(`/api/users/${userId}/delete`, {
            method: 'POST',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache, no-store, must-revalidate'
            },
            credentials: 'same-origin'
        })
        .then(response => {
            console.log("Odpowiedź usuwania status:", response.status);
            if (!response.ok) {
                throw new Error('Status: ' + response.status);
            }
            return response.json();
        })
        .then(data => {
            console.log("Odpowiedź usuwania:", data);
            if (data.status === 'success') {
                showNotification(data.message, 'success');
                loadUsers(); // Odśwież listę użytkowników
            } else {
                showNotification(`Błąd: ${data.message || 'Nieznany błąd'}`, 'error');
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
    // Mapowanie typów na klasy
    const typeClass = {
        'success': 'success',
        'error': 'danger',
        'info': 'info',
        'warning': 'warning'
    };
    
    // Wybór ikony
    const iconClass = {
        'success': 'check-circle',
        'error': 'exclamation-circle',
        'info': 'info-circle',
        'warning': 'exclamation-triangle'
    };
    
    // Domyślny typ, jeśli podany jest nieprawidłowy
    const alertClass = typeClass[type] || 'info';
    const icon = iconClass[type] || 'info-circle';
    
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
    notification.className = `admin-card`;
    notification.style.minWidth = '300px';
    notification.style.marginBottom = '10px';
    notification.style.boxShadow = '0 4px 8px rgba(0,0,0,0.2)';
    notification.style.backgroundColor = 'var(--admin-bg-medium)';
    notification.style.padding = '15px';
    notification.style.borderLeft = `4px solid var(--admin-${alertClass})`;
    notification.innerHTML = `
        <button type="button" class="close" style="color: var(--admin-text);">&times;</button>
        <div>
            <i class="fa fa-${icon}" style="color: var(--admin-${alertClass}); margin-right: 8px;"></i>
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
