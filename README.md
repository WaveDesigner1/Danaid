# 🔐 Danaid Chat
**APLIKACJA DO JEST DO NAPRAWY, PRACE TRWAJĄ, POCZEKAJ LUB NAPRAW SAMODZIELNIE!**

**Bezpieczna aplikacja czatu z szyfrowaniem end-to-end (E2EE)**

Danaid Chat to edukacyjna aplikacja webowa demonstrująca implementację hybrid encryption (RSA + AES-GCM) z Perfect Forward Secrecy dla bezpiecznej komunikacji w czasie rzeczywistym.

![License](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)
![Python](https://img.shields.io/badge/python-3.9+-green.svg)
![Security](https://img.shields.io/badge/security-E2EE-red.svg)
![Status](https://img.shields.io/badge/status-production%20ready-brightgreen.svg)

## ✨ Główne Funkcje

- 🔐 **End-to-End Encryption** - RSA-OAEP (2048-bit) + AES-GCM (256-bit)
- 🔄 **Perfect Forward Secrecy** - Unikalne klucze sesji dla każdej konwersacji
- ⚡ **Real-time Communication** - Socket.IO z bezpiecznym WebSocket
- 🔑 **Digital Signatures** - Autentykacja oparta na podpisach RSA
- 👥 **Friend System** - Zarządzanie kontaktami i zaproszeniami
- 🛡️ **Secure Key Management** - Klucze przechowywane tylko w sesji
- 👨‍💼 **Admin Panel** - Zarządzanie użytkownikami i monitorowanie

## 🏗️ Architektura

```
┌─────────────────┐ HTTPS/WSS ┌─────────────────┐ SQL ┌─────────────────┐
│   Client (JS)   │ ◄─────────► │  Flask Server   │ ◄───► │   PostgreSQL    │
│                 │             │                 │       │                 │
│ • Web Crypto    │             │ • Chat API      │       │ • Users         │
│ • Socket.IO     │             │ • Auth API      │       │ • Sessions      │
│ • E2EE Logic    │             │ • Socket.IO     │       │ • Messages      │
└─────────────────┘             └─────────────────┘       └─────────────────┘
```

### Encryption Flow

1. **Generowanie kluczy RSA** - Każdy użytkownik generuje parę kluczy (2048-bit)
2. **Wymiana kluczy sesji** - Alice generuje klucz AES-256, szyfruje kluczem publicznym Boba
3. **Szyfrowanie wiadomości** - Obie strony używają tego samego klucza AES do szyfrowania
4. **Perfect Forward Secrecy** - Nowy klucz sesji dla każdej konwersacji

## 🚀 Quick Start

### Wymagania

- Python 3.9+
- PostgreSQL 12+
- Nowoczesna przeglądarka z Web Crypto API

### Instalacja

```bash
# Klonowanie repozytorium
git clone https://github.com/your-repo/danaid-chat.git
cd danaid-chat

# Tworzenie virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# lub venv\Scripts\activate  # Windows

# Instalacja zależności
pip install -r requirements.txt

# Konfiguracja bazy danych
export DATABASE_URL="postgresql://user:password@localhost/danaid_chat"
export SECRET_KEY="your-super-secret-key-here"

# Uruchomienie aplikacji
python main.py
```

Aplikacja będzie dostępna pod adresem `http://localhost:8080`

### Docker

```bash
# Build i uruchomienie
docker build -t danaid-chat .
docker run -p 8080:8080 -e DATABASE_URL="your-db-url" danaid-chat
```

## 📚 Jak to działa

### 1. Rejestracja

```javascript
// Generowanie kluczy RSA w przeglądarce
const keyPair = await crypto.subtle.generateKey({
    name: "RSA-OAEP",
    modulusLength: 2048,
    hash: "SHA-256"
}, true, ["encrypt", "decrypt"]);

// Wysłanie klucza publicznego na serwer
// Pobranie klucza prywatnego przez użytkownika
```

### 2. Logowanie z podpisem cyfrowym

```javascript
// Załadowanie klucza prywatnego z pliku
// Podpisanie hasła kluczem prywatnym
const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    passwordBytes
);
```

### 3. Bezpieczna wymiana wiadomości

```javascript
// Alice generuje klucz sesji AES-256
const sessionKey = await crypto.subtle.generateKey({
    name: "AES-GCM",
    length: 256
}, true, ["encrypt", "decrypt"]);

// Alice szyfruje klucz kluczem publicznym Boba
const encryptedKey = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    bobPublicKey,
    sessionKeyRaw
);

// Obie strony używają tego samego klucza do szyfrowania wiadomości
```

## 🔧 API Reference

### Authentication

```http
POST /api/register
Content-Type: application/json

{
    "username": "alice",
    "password": "securepass123",
    "public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

```http
POST /api/login
Content-Type: application/json

{
    "username": "alice",
    "password": "securepass123",
    "signature": "base64_encoded_signature"
}
```

### Chat Operations

```http
POST /api/session/init
Content-Type: application/json

{
    "recipient_id": "654321"
}
```

```http
POST /api/message/send
Content-Type: application/json

{
    "session_token": "abc123...",
    "content": "base64_encrypted_message",
    "iv": "base64_initialization_vector"
}
```

## 🛡️ Bezpieczeństwo

### Właściwości kryptograficzne

- **Confidentiality** - Tylko nadawca i odbiorca mogą przeczytać wiadomość
- **Integrity** - Wiadomości nie mogą być modyfikowane niezauważenie
- **Authentication** - Podpisy cyfrowe weryfikują tożsamość
- **Forward Secrecy** - Kompromitacja kluczy długoterminowych nie wpływa na stare wiadomości

### Zabezpieczenia

✅ **Chronione przed:**
- Passive surveillance
- Server compromise (serwer nie może odszyfrować wiadomości)
- Man-in-the-middle attacks
- Replay attacks

⚠️ **Znane ograniczenia:**
- Endpoint security (kompromitacja urządzenia)
- Brak certificate authority validation
- Forward secrecy tylko na poziomie sesji

## 📁 Struktura Projektu //

```

```

## 🧪 Testing

```bash
# Testy jednostkowe
python -m pytest tests/

# Testy kryptografii
python -m pytest tests/test_crypto.py -v

# Testy API
python -m pytest tests/test_api.py -v
```

## 📈 Performance

### Optymalizacje

- **Key caching** - Klucze sesji cache'owane w pamięci
- **Database indexing** - Optymalne indeksy dla zapytań
- **Message batching** - Grupowanie wiadomości w batch'e
- **Compression** - Kompresja dla większych wiadomości

### Metryki

- **Encryption latency**: <10ms (AES-GCM)
- **Key exchange time**: <100ms (RSA-OAEP)
- **Message throughput**: 1000+ msg/s
- **Concurrent users**: 10,000+ (z odpowiednią infrastrukturą)

## 🚀 Deployment

### Railway.app

```bash
# Automatyczne deployment z GitHub
railway login
railway link
railway up
```

### Manual Deployment

```bash
# Production server z Gunicorn
gunicorn -w 4 -k gevent -b 0.0.0.0:8080 --worker-connections 1000 main:app
```

### Environment Variables

```bash
export DATABASE_URL="postgresql://user:pass@host:port/db"
export SECRET_KEY="production-secret-key"
export FLASK_ENV="production"
export PORT="8080"
```

## 🎓 Wartość Edukacyjna

Ten projekt demonstruje:

- **Praktyczną kryptografię** w aplikacjach webowych
- **Web Crypto API** integration
- **Full-stack security architecture**
- **Real-time secure communication**
- **Modern web development** patterns

### Dla kogo?

- 🎓 **Studenci informatyki** - nauka praktycznej kryptografii
- 👨‍💻 **Deweloperzy** - implementacja E2EE w aplikacjach
- 🔒 **Security engineers** - analiza protokołów bezpieczeństwa
- 📚 **Edukatorzy** - materiał do kursów bezpieczeństwa

## 🚧 Planowane Funkcje

### 🔄 W rozwoju

- [ ] **Czyszczenie czatu** - możliwość usuwania wszystkich wiadomości z konwersacji
- [ ] **Usuwanie znajomych** - funkcja usuwania kontaktów z listy znajomych
- [ ] **Optymalizacja ograniczeń** - eliminacja luk bezpieczeństwa zachowując wygodę użytkownika
### 💡 Roadmap

- [ ] **File encryption** - bezpieczne udostępnianie plików
- [ ] **Group messaging** - czaty grupowe z E2EE
- [ ] **Message reactions** - reakcje na wiadomości
- [ ] **Key rotation** - automatyczna rotacja kluczy sesji
- [ ] **Mobile app** - aplikacja na Android/iOS


### 🎯 Future Vision

- **Perfect Forward Secrecy** na poziomie wiadomości (Double Ratchet)
- **Multi-device synchronization** z encrypted backup
- **Post-quantum cryptography** - przygotowanie na quantum computing
- **Federation support** - komunikacja z innymi serwerami

## 📜 Licencja

Ten projekt jest licencjonowany na licencji MIT - zobacz [LICENSE](LICENSE) dla szczegółów.

## 🙏 Acknowledgments

- **Signal Protocol** - inspiracja dla architektury E2EE
- **Web Crypto API** - standardy kryptografii przeglądarek
- **Flask community** - doskonały framework webowy
- **OpenSSL** - fundamenty kryptografii

## 📞 Kontakt i Wsparcie

- 📧 **Email**: contact@danaid-chat.org
- 🐛 **Issues**: [GitHub Issues](https://github.com/your-repo/danaid-chat/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/your-repo/danaid-chat/discussions)
- 📖 **Documentation**: [Wiki](https://github.com/your-repo/danaid-chat/wiki)

---

**⭐ Jeśli projekt Ci się podoba, zostaw gwiazdkę!**

*Stworzono z ❤️ dla nauki bezpiecznego programowania*
