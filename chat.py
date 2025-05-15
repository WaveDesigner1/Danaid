from flask import Blueprint, render_template
from flask_login import login_required, current_user

chat_bp = Blueprint('chat', __name__)

@chat_bp.route('/chat')
@login_required
def chat():
    """Główna strona czatu - dostęp tylko dla zalogowanych użytkowników"""
    return render_template('chat.html')
