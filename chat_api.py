from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from models import User, ChatSession, Message, db
import datetime
import hashlib
import json

chat_api = Blueprint('chat_api', __name__)

@chat_api.route('/api/user/<user_id>/public_key', methods=['GET'])
@login_required
def get_user_public_key(user_id):
    """Pobiera klucz publiczny użytkownika"""
    user = User.query.filter_by(user_id=user_id).first()
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
        
    return jsonify({
        'status': 'success',
        'user_id': user.user_id,
        'username': user.username,
        'public_key': user.public_key
    })

@chat_api.route('/api/users', methods=['GET'])
@login_required
def get_users():
    """Pobiera listę wszystkich użytkowników (poza sobą)"""
    users = User.query.filter(User.id != current_user.id).all()
    
    user_list = [{
        'id': user.id,
        'user_id': user.user_id,
        'username': user.username,
        
    } for user in users]
    
    return jsonify({
        'status': 'success',
        'users': user_list
    })

@chat_api.route('/api/online_users', methods=['GET'])
@login_required
def get_online_users():
    """Pobiera listę użytkowników online"""
    try:
        # Sprawdź czy kolumna is_online istnieje w modelu
        if hasattr(User, 'is_online'):
            online_users = User.query.filter(User.is_online == True, User.id != current_user.id).all()
            
            user_list = [{
                'id': user.id,
                'user_id': user.user_id,
                'username': user.username,
            } for user in online_users]
            
            return jsonify({
                'status': 'success',
                'online_users': user_list
            })
        else:
            # Jeśli kolumna nie istnieje, zwróć pustą listę
            return jsonify({
                'status': 'success',
                'online_users': [],
                'message': 'Funkcja statusu online nie jest dostępna'
            })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_api.route('/api/session/init', methods=['POST'])
@login_required
def init_chat_session():
    """Inicjuje nową sesję czatu z innym użytkownikiem"""
    data = request.get_json()
    
    recipient_id = data.get('recipient_id')
    if not recipient_id:
        return jsonify({'status': 'error', 'message': 'Nie podano ID adresata'}), 400
        
    # Znajdź użytkownika, do którego chcemy pisać
    recipient = User.query.filter_by(user_id=recipient_id).first()
    if not recipient:
        return jsonify({'status': 'error', 'message': 'Adresat nie istnieje'}), 404
        
    # Sprawdź, czy nie ma już aktywnej sesji między tymi użytkownikami
    existing_session = ChatSession.query.filter(
        ((ChatSession.initiator_id == current_user.id) & (ChatSession.recipient_id == recipient.id)) |
        ((ChatSession.initiator_id == recipient.id) & (ChatSession.recipient_id == current_user.id))
    ).filter(ChatSession.is_active == True, ChatSession.expires_at > datetime.datetime.utcnow()).first()
    
    if existing_session:
        # Jeśli istnieje aktywna sesja, odśwież ją
        existing_session.refresh_session()
        return jsonify({
            'status': 'success',
            'message': 'Sesja odświeżona',
            'session': {
                'id': existing_session.id,
                'token': existing_session.session_token,
                'expires_at': existing_session.expires_at.isoformat(),
                'initiator_id': existing_session.initiator_id,
                'recipient_id': existing_session.recipient_id
            }
        })
    
    # Utwórz nową sesję
    new_session = ChatSession.create_session(current_user.id, recipient.id)
    
    return jsonify({
        'status': 'success',
        'message': 'Sesja utworzona',
        'session': {
            'id': new_session.id,
            'token': new_session.session_token,
            'expires_at': new_session.expires_at.isoformat(),
            'initiator_id': new_session.initiator_id,
            'recipient_id': new_session.recipient_id
        }
    }), 201

@chat_api.route('/api/session/<session_token>/validate', methods=['GET'])
@login_required
def validate_session(session_token):
    """Sprawdza ważność sesji czatu"""
    session = ChatSession.query.filter_by(session_token=session_token).first()
    
    if not session:
        return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
        
    # Sprawdź czy użytkownik jest uczestnikiem tej sesji
    if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Brak dostępu do tej sesji'}), 403
        
    # Sprawdź ważność sesji
    if not session.is_valid:
        return jsonify({'status': 'error', 'message': 'Sesja wygasła'}), 401
        
    # Odśwież sesję
    session.last_activity = datetime.datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'session': {
            'id': session.id,
            'token': session.session_token,
            'expires_at': session.expires_at.isoformat(),
            'initiator_id': session.initiator_id,
            'recipient_id': session.recipient_id,
            'is_valid': session.is_valid
        }
    })

@chat_api.route('/api/session/<session_token>/close', methods=['POST'])
@login_required
def close_session(session_token):
    """Zamyka sesję czatu"""
    session = ChatSession.query.filter_by(session_token=session_token).first()
    
    if not session:
        return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
        
    # Sprawdź czy użytkownik jest uczestnikiem tej sesji
    if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Brak dostępu do tej sesji'}), 403
        
    # Zamknij sesję
    session.invalidate()
    
    return jsonify({
        'status': 'success',
        'message': 'Sesja zamknięta'
    })
