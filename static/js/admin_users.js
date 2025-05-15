/**
 * Admin Users - skrypt do zarządzania użytkownikami w panelu administratora
 */
document.addEventListener('DOMContentLoaded', function() {
    // Inicjalizacja
    loadUsers();

    // Obsługa kliknięcia przycisku odświeżenia użytkowników
    const refreshButton = document.getElementById('refresh-users');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            loadUsers();
        });
    }
});

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
    
    // Dodaj parametr timestamp, aby uniknąć cachowania
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
        
        // Wyświetl użytkowników
        users.forEach(user => {
            const row = document.createElement('tr');
            row.className = 'user-row';
            row.setAttribute('data-user-id', user.id);
            
            // Pobierz ID aktualnego użytkownika z sessionStorage
            const currentUserId = parseInt(sessionStorage.getItem('user_id'));
            
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
                        <button class="btn btn-sm ${user.is_admin ? 'btn-warning' : 'btn-success'}" onclick="toggleAdmin(${user.id}, '${user.username}')">
                            ${user.is_admin ? '<i class="fa fa-times"></i> Odbierz uprawnienia' : '<i class="fa fa-check"></i> Nadaj uprawnienia'}
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="deleteUser(${user.id}, '${user.username}')">
                            <i class="fa fa-trash"></i> Usuń
                        </button>
                    `}
                </td>
            `;
            
            usersTable.appendChild(row);
        });
    })
    .catch(error => {
        console.error('Błąd:', error);
        usersTable.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Błąd: ${error.message}</td></tr>`;
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
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                showNotification(data.message, 'success');
                loadUsers(); // Odśwież listę użytkowników
            } else {
                showNotification(`Błąd: ${data.message}`, 'error');
            }
        })
        .catch(error => {
            console.error('Błąd:', error);
            showNotification('Wystąpił błąd podczas zmiany uprawnień', 'error');
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
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                showNotification(data.message, 'success');
                loadUsers(); // Odśwież listę użytkowników
            } else {
                showNotification(`Błąd: ${data.message}`, 'error');
            }
        })
        .catch(error => {
            console.error('Błąd:', error);
            showNotification('Wystąpił błąd podczas usuwania użytkownika', 'error');
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
        notificationsContainer.removeChild(notification);
    });
}
