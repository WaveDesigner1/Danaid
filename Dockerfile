FROM python:3.9-slim

WORKDIR /app

# Skopiuj requirements.txt i zainstaluj zależności
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Skopiuj resztę aplikacji
COPY . .

# Ekspozycja portów
EXPOSE 8080 8081

# Uruchom aplikację
CMD ["python", "main.py"]
