// Admin panel JavaScript dla zarządzania użytkownikami

document.addEventListener('DOMContentLoaded', function() {
    loadUsers();

    // Obsługa kliknięcia przycisku odświeżenia użytkowników
    const refreshButton = document.getElementById('refresh-users');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            loadUsers();
        });
    }
});

// Funkcja do pobierania i wyświetlania listy użytkowników
function loadUsers() {
    const usersTable = document.getElementById('users-table-body');
    
    if (!usersTable) {
        console.error('Nie znaleziono tabeli użytkowników');
        return;
    }
    
    // Pokaż loader
    usersTable.innerHTML = '<tr><td colspan="6" class="text-center"><i class="fa fa-spinner fa-spin"></i> Ładowanie użytkowników...</td></tr>';
    
    fetch('/api/users', {
        method: 'GET',
        credentials: 'same-origin'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Błąd pobierania listy użytkowników');
        }
        return response.json();
    })
    .then(users => {
        usersTable.innerHTML = '';
        
        if (users.length === 0) {
            usersTable.innerHTML = '<tr><td colspan="6" class="text-center">Brak użytkowników</td></tr>';
            return;
        }
        
        // Wyświetl użytkowników
        users.forEach(user => {
            const row = document.createElement('tr');
            row.className = 'user-row';
            row.setAttribute('data-user-id', user.id);
            
            // Zablokuj usuwanie własnego konta
            const isCurrentUser = parseInt(sessionStorage.getItem('user_id')) === user.id;
            
            row.innerHTML = `
                <td>${user.id}</td>
                <td class="username">${user.username}</td>
                <td>${user.user_id}</td>
                <td>${user.is_online ? '<span class="label label-success">Online</span>' : '<span class="label label-default">Offline</span>'}</td>
                <td>${user.is_admin ? '<span class="label label-primary">Administrator</span>' : '<span class="label label-default">Użytkownik</span>'}</td>
                <td class="user-actions">
                    ${isCurrentUser ? '' : `<button class="btn btn-sm ${user.is_admin ? 'btn-warning' : 'btn-success'}" onclick="toggleAdmin(${user.id}, '${user.username}')">
                        ${user.is_admin ? 'Odbierz uprawnienia' : 'Nadaj uprawnienia'}
                    </button>`}
                    ${isCurrentUser ? '' : `<button class="btn btn-sm btn-danger" onclick="deleteUser(${user.id}, '${user.username}')">
                        Usuń
                    </button>`}
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

// Funkcja do zmiany uprawnień administratora
function toggleAdmin(userId, username) {
    if (confirm(`Czy na pewno chcesz zmienić uprawnienia użytkownika ${username}?`)) {
        fetch(`/api/users/${userId}/toggle_admin`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
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

// Funkcja do usuwania użytkownika
function deleteUser(userId, username) {
    if (confirm(`Czy na pewno chcesz usunąć użytkownika ${username}? To działanie jest nieodwracalne.`)) {
        fetch(`/api/users/${userId}/delete`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
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

// Funkcja do wyświetlania powiadomień
function showNotification(message, type = 'info') {
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
    notification.className = `alert alert-${type === 'error' ? 'danger' : type}`;
    notification.style.minWidth = '300px';
    notification.style.marginBottom = '10px';
    notification.innerHTML = `
        <button type="button" class="close" data-dismiss="alert">&times;</button>
        ${message}
    `;
    
    // Dodaj powiadomienie do kontenera
    notificationsContainer.appendChild(notification);
    
    // Automatycznie zamknij po 5 sekundach
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transition = 'opacity 0.5s';
        setTimeout(() => {
            notificationsContainer.removeChild(notification);
        }, 500);
    }, 5000);
    
    // Obsługa przycisku zamknięcia
    const closeButton = notification.querySelector('.close');
    closeButton.addEventListener('click', function() {
        notificationsContainer.removeChild(notification);
    });
}
