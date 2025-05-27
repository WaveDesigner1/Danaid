/**
 * Webshell - skrypt do obsługi konsoli webshell w panelu administratora
 */
document.addEventListener('DOMContentLoaded', function() {
    const commandInput = document.getElementById('command-input');
    const executeBtn = document.getElementById('execute-btn');
    const terminalOutput = document.getElementById('terminal-output');
    const outputText = document.getElementById('output-text');
    
    // Historia komend
    let commandHistory = [];
    let historyIndex = -1;
    
    // Automatycznie ustaw focus na polu wejściowym
    commandInput.focus();
    
    // Obsługa przycisku wykonania
    executeBtn.addEventListener('click', function() {
        executeCommand();
    });
    
    // Obsługa klawisza Enter
    commandInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            executeCommand();
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            navigateHistory(-1); // w górę historii
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            navigateHistory(1);  // w dół historii
        }
    });
    
    // Funkcja wykonująca komendę
    function executeCommand() {
        const command = commandInput.value.trim();
        
        if (!command) return;
        
        // Dodaj komendę do historii
        commandHistory.unshift(command);
        historyIndex = -1;
        
        // Ogranicz historię do 20 komend
        if (commandHistory.length > 20) {
            commandHistory.pop();
        }
        
        // Wyślij żądanie AJAX
        fetch('/flask_admin/webshell/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: 'command=' + encodeURIComponent(command)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Błąd serwera: ' + response.status);
            }
            return response.text();
        })
        .then(html => {
            // Wyodrębnij wynik z odpowiedzi HTML używając parsera DOM
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const resultElement = doc.querySelector('.well');
            
            if (resultElement) {
                // Pokaż kontener wyjścia
                terminalOutput.style.display = 'block';
                
                // Ustaw wynik
                outputText.textContent = '$ ' + command + '\n\n' + resultElement.textContent;
                
                // Przewiń do najnowszego wyjścia
                terminalOutput.scrollTop = terminalOutput.scrollHeight;
            } else {
                // Jeśli nie znaleziono wyniku, prawdopodobnie wystąpił błąd
                terminalOutput.style.display = 'block';
                outputText.textContent = '$ ' + command + '\n\nNie udało się przetworzyć wyniku.';
            }
            
            // Wyczyść pole wejściowe i ustaw focus
            commandInput.value = '';
            commandInput.focus();
        })
        .catch(error => {
            console.error('Błąd:', error);
            terminalOutput.style.display = 'block';
            outputText.textContent = '$ ' + command + '\n\nBłąd: ' + error.message;
            
            // Wyczyść pole wejściowe i ustaw focus
            commandInput.value = '';
            commandInput.focus();
        });
    }
    
    // Funkcja do nawigacji po historii komend
    function navigateHistory(direction) {
        // direction: -1 = góra (starsze), 1 = dół (nowsze)
        if (commandHistory.length === 0) return;
        
        // Zaktualizuj indeks
        historyIndex = Math.max(-1, Math.min(commandHistory.length - 1, historyIndex + direction));
        
        // Ustaw komendę z historii lub wyczyść
        if (historyIndex === -1) {
            commandInput.value = '';
        } else {
            commandInput.value = commandHistory[historyIndex];
        }
        
        // Ustaw kursor na końcu tekstu
        setTimeout(() => {
            commandInput.selectionStart = commandInput.selectionEnd = commandInput.value.length;
        }, 0);
    }
});
