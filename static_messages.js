/**
 * Definicje wszystkich komunikatów aplikacji
 * Dzięki temu wszystkie komunikaty są w jednym miejscu i łatwo je zmienić
 */
const MESSAGES = {
    // Komunikaty błędów rejestracji
    'missing_data': 'Brakuje wymaganych danych. Wypełnij wszystkie pola formularza.',
    'user_exists': 'Użytkownik o podanej nazwie już istnieje. Wybierz inną nazwę użytkownika.',
    'invalid_key_format': 'Nieprawidłowy format klucza publicznego.',
    'db_error': 'Wystąpił błąd podczas zapisywania danych. Spróbuj ponownie później.',

    // Komunikaty błędów logowania
    'invalid_credentials': 'Niepoprawne dane logowania. Sprawdź nazwę użytkownika i hasło.',
    'invalid_password': 'Niepoprawne hasło. Spróbuj ponownie.',
    'invalid_signature': 'Niepoprawny podpis cyfrowy. Upewnij się, że używasz właściwego klucza prywatnego.',
    'verification_error': 'Błąd weryfikacji podpisu. Spróbuj ponownie.',

    // Komunikaty błędów ogólnych
    'user_not_found': 'Nie znaleziono użytkownika o podanej nazwie.',
    
    // Komunikaty błędów administratora
    'invalid_password': 'Nieprawidłowe hasło administratora.',
    'admin_exists': 'Administrator już istnieje w systemie.',
    'admin_user_missing': 'Najpierw utwórz konto użytkownika "admin".',

    // Komunikaty sukcesu
    'registration_ok': 'Zarejestrowano pomyślnie! Zapamiętaj swój identyfikator użytkownika.',
    'login_ok': 'Zalogowano pomyślnie. Przekierowuję do panelu czatu...',
    'admin_setup_ok': 'Administrator skonfigurowany pomyślnie.'
};

/**
 * Funkcja zwracająca komunikat na podstawie kodu
 * @param {string} code - kod komunikatu
 * @returns {string} - treść komunikatu
 */
function getMessage(code) {
    return MESSAGES[code] || 'Wystąpił nieznany błąd. Spróbuj ponownie później.';
}
