from app import create_app
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Pobierz URL bazy danych ze zmiennych środowiskowych
database_url = os.environ.get('DATABASE_URL', 'postgresql://danaid_database_owner:npg_LcawRkg3jpD2@ep-yellow-block-a4fc64bc-pooler.us-east-1.aws.neon.tech/danaid_database?sslmode=require')

# Popraw URL jeśli zaczyna się od "postgres://"
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

from app import create_app

# Uruchomienie aplikacji
app = create_app()

# Wymuszenie ustawienia bazy danych
app.config['SQLALCHEMY_DATABASE_URI'] = database_url

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
