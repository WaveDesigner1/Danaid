
from flask import Blueprint, render_template
from flask_login import login_required

chat_bp = Blueprint('chat', __name__)

@chat_bp.route("/chat")
@login_required
def chat():
    return render_template("chat.html")