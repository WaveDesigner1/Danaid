from app import create_app, db
from models import User
from werkzeug.security import generate_password_hash
import os
import secrets
import time

app = create_app()

if __name__ == '__main__':
    # Uruchomienie aplikacji
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
