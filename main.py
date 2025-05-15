from app import create_app
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Wymuszenie konfiguracji przed importem aplikacji
os.environ['DATABASE_URL'] = 'postgresql://danaid_database_owner:npg_LcawRkg3jpD2@ep-yellow-block-a4fc64bc-pooler.us-east-1.aws.neon.tech/danaid_database?sslmode=require'
os.environ['FORCE_POSTGRESQL'] = 'true'

# Wyświetl wartość zmiennej (dla debugowania)
print(f"DATABASE_URL = {os.environ.get('DATABASE_URL')}")

from app import create_app

# Uruchomienie aplikacji
app = create_app()

# Wymuszenie ustawienia bazy danych
app.config['SQLALCHEMY_DATABASE_URI'] = database_url

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
