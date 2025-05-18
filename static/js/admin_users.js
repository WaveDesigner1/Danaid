/**
 * Admin Users - skrypt do zarządzania użytkownikami w panelu administratora
 * Wersja uproszczona i naprawiona
 */

// Inicjalizacja przy załadowaniu strony
document.addEventListener('DOMContentLoaded', function() {
    console.log("Admin panel initialized");
    
    // Zainicjuj liczniki statystyk
    resetCounters();
    
    // Załaduj dane użytkowników
    loadUsers();
    
    // Odświeżaj co 30 sekund
    setInterval(loadUsers, 30000);
    
    // Obsługa przycisku odświeżania
    const refreshButton = document.getElementById('refresh-users');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            console.log("Manual refresh triggered");
            loadUsers();
        });
    }
});

// Funkcja do resetowania liczników na "-" zamiast "..."
function resetCounters() {
    const counters = ['users-count', 'sessions-count', 'messages-count', 'online-count'];
    counters.forEach(id => {
        const element = document.getElementById(id);
        if (element) element.textContent = "-";
    });
}

// Główna funkcja do ładowania użytkowników
function loadUsers() {
    console.log("Loading users...");
    
    // Pobierz tabelę użytkowników
    const usersTable = document.getElementById('users-table-body');
    if (!usersTable) {
        console.error("Users table not found");
        return;
    }
    
    // Wyświetl komunikat o ładowaniu
    usersTable.innerHTML = '<tr><td colspan="6" class="text-center"><i class="fa fa-spinner fa-spin"></i> Ładowanie użytkowników...</td></tr>';
    
    // Dodaj timestamp, aby uniknąć cachowania
    const timestamp = new Date().getTime();
    
    // Wykonaj zapytanie z dodatkowymi nagłówkami przeciw cachowaniu
    fetch('/api/users?' + timestamp, {
        method: 'GET',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        },
        credentials: 'same-origin'
    })
    .then(function(response) {
        console.log("API response status:", response.status);
        
        if (!response.ok) {
            throw new Error('HTTP status: ' + response.status);
        }
        
        return response.json();
    })
    .then(function(data) {
        console.log("Received data:", typeof data, Array.isArray(data) ? data.length : 'not array');
        
        // Sprawdź, czy mamy prawidłowe dane
        if (!data) {
            throw new Error('Brak danych');
        }
        
        // Obsługa błędu zwróconego przez API
        if (data.error) {
            throw new Error(data.error);
        }
        
        // Sprawdź, czy dane są tablicą
        if (!Array.isArray(data)) {
            throw new Error('Nieprawidłowy format danych (oczekiwano tablicy)');
        }
        
        // Aktualizuj liczniki niezależnie od dalszego przetwarzania
        updateCounters(data);
        
        // Wyczyść tabelę
        usersTable.innerHTML = '';
        
        // Jeśli lista jest pusta
        if (data.length === 0) {
            usersTable.innerHTML = '<tr><td colspan="6" class="text-center">Brak użytkowników</td></tr>';
            return;
        }
        
        // Renderuj wiersze dla każdego użytkownika
        data.forEach(function(user) {
            // Upewnij się, że wszystkie pola istnieją
            const safeUser = {
                id: user.id || 0,
                username: user.username || 'Brak nazwy',
                user_id: user.user_id || (user.id ? user.id.toString() : '0'),
                is_admin: Boolean(user.is_admin),
                is_online: Boolean(user.is_online)
            };
            
            // Sprawdź, czy to aktualny użytkownik
            const currentUserId = parseInt(sessionStorage.getItem('user_id') || '0');
            const isCurrentUser = currentUserId === safeUser.id;
            
            // Utwórz wiersz dla użytkownika
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${safeUser.id}</td>
                <td>${safeUser.username}</td>
                <td>${safeUser.user_id}</td>
                <td>${safeUser.is_online ? 
                    '<span class="admin-badge success">Online</span>' : 
                    '<span class="admin-badge secondary">Offline</span>'}
                </td>
                <td>${safeUser.is_admin ? 
                    '<span class="admin-badge primary">Administrator</span>' : 
                    '<span class="admin-badge secondary">Użytkownik</span>'}
                </td>
                <td>
                    ${isCurrentUser ? 
                    '<em>Aktualny użytkownik</em>' : 
                    `<button class="admin-btn ${safeUser.is_admin ? 'warning' : 'success'} admin-btn-sm" onclick="toggleAdmin(${safeUser.id}, '${safeUser.username}')">
                        ${safeUser.is_admin ? '<i class="fa fa-times"></i> Odbierz uprawnienia' : '<i class="fa fa-check"></i> Nadaj uprawnienia'}
                     </button>
                     <button class="admin-btn danger admin-btn-sm" onclick="deleteUser(${safeUser.id}, '${safeUser.username}')">
                        <i class="fa fa-trash"></i> Usuń
                     </button>`}
                </td>
            `;
            
            usersTable.appendChild(row);
        });
        
        console.log("Users loaded successfully");
    })
    .catch(function(error) {
        console.error("Error loading users:", error);
        
        // Wyświetl błąd w tabeli
        usersTable.innerHTML = `
            <tr>
                <td colspan="6" class="text-center text-danger">
                    <i class="fa fa-exclamation-circle"></i> Błąd ładowania: ${error.message}
                </td>
            </tr>
        `;
        
        // Zresetuj liczniki w przypadku błędu
        resetCounters();
    });
}

// Funkcja do aktualizacji liczników
function updateCounters(users) {
    console.log("Updating counters with", users.length, "users");
    
    const usersCountElement = document.getElementById('users-count');
    const onlineCountElement = document.getElementById('online-count');
    
    if (usersCountElement) {
        usersCountElement.textContent = users.length.toString();
    }
    
    if (onlineCountElement) {
        const onlineUsers = users.filter(user => user && user.is_online).length;
        onlineCountElement.textContent = onlineUsers.toString();
    }
    
    // Placeholder dla innych liczników
    const sessionsCountElement = document.getElementById('sessions-count');
    const messagesCountElement = document.getElementById('messages-count');
    
    if (sessionsCountElement) sessionsCountElement.textContent = "-";
    if (messagesCountElement) messagesCountElement.textContent = "-";
}

// Funkcja do zmiany uprawnień administratora
function toggleAdmin(userId, username) {
    console.log("Toggling admin for user:", userId, username);
    
    if (!confirm(`Czy na pewno chcesz zmienić uprawnienia administratora dla użytkownika "${username}"?`)) {
        return;
    }
    
    fetch(`/api/users/${userId}/toggle_admin`, {
        method: 'POST',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/json'
        },
        credentials: 'same-origin'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('HTTP status: ' + response.status);
        }
        return response.json();
    })
    .then(data => {
        if (data.status === 'success') {
            alert(data.message || 'Uprawnienia zostały zmienione');
            loadUsers(); // Odśwież listę
        } else {
            alert('Błąd: ' + (data.message || 'Nieznany błąd'));
        }
    })
    .catch(error => {
        console.error('Error toggling admin:', error);
        alert('Wystąpił błąd: ' + error.message);
    });
}

// Funkcja do usuwania użytkownika
function deleteUser(userId, username) {
    console.log("Deleting user:", userId, username);
    
    if (!confirm(`Czy na pewno chcesz usunąć użytkownika "${username}"? Ta operacja jest nieodwracalna.`)) {
        return;
    }
    
    fetch(`/api/users/${userId}/delete`, {
        method: 'POST',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/json'
        },
        credentials: 'same-origin'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('HTTP status: ' + response.status);
        }
        return response.json();
    })
    .then(data => {
        if (data.status === 'success') {
            alert(data.message || 'Użytkownik został usunięty');
            loadUsers(); // Odśwież listę
        } else {
            alert('Błąd: ' + (data.message || 'Nieznany błąd'));
        }
    })
    .catch(error => {
        console.error('Error deleting user:', error);
        alert('Wystąpił błąd: ' + error.message);
    });
}
Główne zmiany
