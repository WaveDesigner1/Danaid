import os

# Pobierz URL bazy danych ze zmiennych środowiskowych
database_url = os.environ.get('DATABASE_URL', 'postgresql://danaid_database_owner:npg_u5RNUlCmqrz7@ep-winter-wildflower-a4fu4o91-pooler.us-east-1.aws.neon.tech/danaid_database?sslmode=require')

# Popraw URL jeśli zaczyna się od "postgres://"
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

from app import create_app

# Utworzenie aplikacji
app = create_app()

# Wymuszenie ustawienia bazy danych - użyj zdefiniowanej wcześniej zmiennej database_url
app.config['SQLALCHEMY_DATABASE_URI'] = database_url

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
