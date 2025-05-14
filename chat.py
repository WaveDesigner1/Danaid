from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from models import User, ChatSession, Message, db
import datetime
import json

chat_bp = Blueprint('chat', __name__)

@chat_bp.route('/chat')
@login_required
def chat():
    """Główna strona czatu"""
    return render_template('chat.html')

@chat_bp.route('/find_user', methods=['POST'])
@login_required
def find_user():
    """Wyszukuje użytkownika po ID"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Brak ID użytkownika'}), 400
            
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            return jsonify({
                'status': 'error', 
                'message': 'Nie znaleziono użytkownika'
            }), 404
            
        # Nie zwracaj danych własnego konta
        if user.id == current_user.id:
            return jsonify({
                'status': 'error', 
                'message': 'Nie możesz rozmawiać sam ze sobą'
            }), 400
            
        return jsonify({
            'status': 'success',
            'user': {
                'username': user.username,
                'user_id': user.user_id,
                'is_online': getattr(user, 'is_online', False)
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/add_friend', methods=['POST'])
@login_required
def add_friend():
    """Dodaje użytkownika do znajomych (tworzy nową sesję czatu)"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Brak ID użytkownika'}), 400
            
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            return jsonify({
                'status': 'error', 
                'message': 'Nie znaleziono użytkownika'
            }), 404
            
        # Sprawdź czy sesja już istnieje
        existing_session = ChatSession.query.filter(
            ((ChatSession.initiator_id == current_user.id) & (ChatSession.recipient_id == user.id)) |
            ((ChatSession.initiator_id == user.id) & (ChatSession.recipient_id == current_user.id))
        ).first()
        
        if existing_session:
            # Jeśli sesja istnieje, ale jest nieaktywna, aktywuj ją ponownie
            if not existing_session.is_active:
                existing_session.is_active = True
                existing_session.expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                db.session.commit()
                
            return jsonify({
                'status': 'success',
                'message': 'Sesja czatu już istnieje',
                'session_id': existing_session.id
            })
            
        # Utwórz nową sesję
        session = ChatSession.create_session(current_user.id, user.id)
        
        return jsonify({
            'status': 'success',
            'message': 'Dodano do znajomych',
            'session_id': session.id
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/get_friends')
@login_required
def get_friends():
    """Zwraca listę znajomych (aktywne sesje czatu)"""
    try:
        # Pobierz aktywne sesje
        sessions = ChatSession.get_active_sessions(current_user.id)
        
        friends = []
        for session in sessions:
            # Określ, kto jest znajomym w tej sesji
            friend_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
            friend = User.query.get(friend_id)
            
            if friend:
                # Pobierz liczbę nieprzeczytanych wiadomości
                unread_count = Message.query.filter(
                    (Message.session_id == session.id) &
                    (Message.sender_id == friend.id) &
                    (Message.read == False)
                ).count()
                
                friends.append({
                    'username': friend.username,
                    'user_id': friend.user_id,
                    'is_online': getattr(friend, 'is_online', False),
                    'last_active': friend.last_active.isoformat() if hasattr(friend, 'last_active') else None,
                    'session_id': session.id,
                    'unread_count': unread_count
                })
        
        return jsonify({
            'status': 'success',
            'friends': friends
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/send_message', methods=['POST'])
@login_required
def send_message():
    """Wysyła zaszyfrowaną wiadomość"""
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        encrypted_content = data.get('content')
        iv = data.get('iv')
        
        if not session_id or not encrypted_content or not iv:
            return jsonify({'status': 'error', 'message': 'Niepełne dane'}), 400
            
        # Sprawdź, czy sesja istnieje i czy użytkownik ma do niej dostęp
        session = ChatSession.query.get(session_id)
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do sesji'}), 403
            
        # Sprawdź, czy sesja jest ważna
        if not session.is_valid:
            return jsonify({'status': 'error', 'message': 'Sesja wygasła'}), 400
            
        # Utwórz nową wiadomość
        message = Message(
            session_id=session_id,
            sender_id=current_user.id,
            content=encrypted_content,
            iv=iv
        )
        
        # Odśwież sesję
        session.refresh_session()
        
        # Dodaj wiadomość do bazy
        db.session.add(message)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message_id': message.id,
            'timestamp': message.timestamp.isoformat()
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/get_messages/<int:session_id>')
@login_required
def get_messages(session_id):
    """Pobiera wiadomości z danej sesji"""
    try:
        # Sprawdź, czy sesja istnieje i czy użytkownik ma do niej dostęp
        session = ChatSession.query.get(session_id)
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do sesji'}), 403
            
        # Pobierz wiadomości
        messages = Message.query.filter_by(session_id=session_id).order_by(Message.timestamp).all()
        
        # Sformatuj wiadomości do JSON
        messages_json = []
        for msg in messages:
            messages_json.append({
                'id': msg.id,
                'sender_id': msg.sender_id,
                'is_mine': msg.sender_id == current_user.id,
                'content': msg.content,
                'iv': msg.iv,
                'timestamp': msg.timestamp.isoformat(),
                'read': msg.read
            })
            
        return jsonify({
            'status': 'success',
            'messages': messages_json
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/mark_as_read/<int:session_id>', methods=['POST'])
@login_required
def mark_as_read(session_id):
    """Oznacza wiadomości jako przeczytane"""
    try:
        # Sprawdź, czy sesja istnieje i czy użytkownik ma do niej dostęp
        session = ChatSession.query.get(session_id)
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do sesji'}), 403
            
        # Oznacz nieprzeczytane wiadomości od drugiej osoby jako przeczytane
        messages = Message.query.filter(
            (Message.session_id == session_id) &
            (Message.sender_id != current_user.id) &
            (Message.read == False)
        ).all()
        
        for msg in messages:
            msg.read = True
            
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'marked_count': len(messages)
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/delete_session/<int:session_id>', methods=['POST'])
@login_required
def delete_session(session_id):
    """Usuwa (dezaktywuje) sesję czatu"""
    try:
        # Sprawdź, czy sesja istnieje i czy użytkownik ma do niej dostęp
        session = ChatSession.query.get(session_id)
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do sesji'}), 403
            
        # Dezaktywuj sesję
        session.is_active = False
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Sesja usunięta'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
