@echo off
:: Danaid Chat - Windows Startup Script

echo 🚀 Danaid Chat - Starting Application
echo =====================================

:: Sprawdź czy main.py istnieje
if not exist "main.py" (
    echo ❌ Error: main.py not found. Run this script from project directory.
    pause
    exit /b 1
)

:: Sprawdź czy venv istnieje, jeśli nie - utwórz
if not exist "venv" (
    echo 📦 Creating virtual environment...
    python -m venv venv
    echo ✅ Virtual environment created
)

:: Aktywuj venv
echo 🔧 Activating virtual environment...
call venv\Scripts\activate

:: Zainstaluj/zaktualizuj zależności
if exist "requirements.txt" (
    echo 📚 Installing/updating dependencies...
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    echo ✅ Dependencies installed
) else (
    echo ⚠️  Warning: requirements.txt not found
)

:: Sprawdź czy .env istnieje
if not exist ".env" (
    echo 🔧 Creating basic .env file...
    (
    echo # Danaid Chat Configuration
    echo PORT=8080
    echo FLASK_DEBUG=true
    echo FLASK_ENV=development
    echo SECRET_KEY=your-secret-key-change-me-please
    echo DATABASE_URL=sqlite:///danaid_local.db
    ) > .env
    echo ✅ Basic .env created ^(remember to configure it!^)
)

:: Uruchom aplikację
echo 🚀 Starting Danaid Chat...
echo =====================================
python main.py

:: Pauza żeby zobaczyć błędy jeśli wystąpią
if errorlevel 1 (
    echo.
    echo ❌ Application ended with error
    pause
)