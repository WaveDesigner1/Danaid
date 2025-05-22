FROM python:3.9-slim

# Ustaw zmienne środowiskowe
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Utwórz użytkownika nieroot (bezpieczeństwo)
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Utwórz katalog roboczy
WORKDIR /app

# Zainstaluj zależności systemowe (jeśli potrzebne)
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Skopiuj i zainstaluj zależności Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Skopiuj kod aplikacji
COPY . .

# Zmień właściciela plików na appuser
RUN chown -R appuser:appuser /app
USER appuser

# Ekspozycja portów
EXPOSE 8080 8081

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# Uruchom aplikację
CMD ["python", "main.py"]
