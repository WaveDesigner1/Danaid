from flask import Blueprint, render_template
from flask_login import login_required, current_user

chat_bp = Blueprint('chat', __name__)

@chat_bp.route('/chat')
@login_required
def chat():
    """Główna strona czatu"""
    return render_template('chat.html')

@chat_bp.route('/admin_panel')
@login_required
def admin_panel():
    """Ta funkcja powoduje konflikt z funkcją w app.py"""
    # Przekieruj do nowej funkcji w app.py
    from flask import redirect, url_for
    return redirect(url_for('admin_dashboard'))
