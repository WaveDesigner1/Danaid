from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import db, User, ChatSession, Message
import datetime

chat_api = Blueprint('chat_api', __name__, url_prefix='/api/chat')

@chat_api.route('/session/<user_id>', methods=['GET', 'POST'])
@login_required
def get_or_create_session(user_id):
    """
    Pobiera lub tworzy sesję czatu z określonym użytkownikiem.
    GET: Pobiera istniejącą sesję
    POST: Tworzy nową sesję
    """
    try:
        # Znajdź użytkownika po user_id
        recipient = User.query.filter_by(user_id=user_id).first()
        if not recipient:
            return jsonify({'status': 'error', 'message': 'Użytkownik nie istnieje'}), 404
            
        # Nie pozwól na czat z samym sobą
        if recipient.id == current_user.id:
            return jsonify({'status': 'error', 'message': 'Nie możesz rozpocząć czatu z samym sobą'}), 400
        
        # Sprawdź, czy istnieje aktywna sesja
        existing_session = ChatSession.query.filter(
            ((ChatSession.initiator_id == current_user.id) & (ChatSession.recipient_id == recipient.id)) |
            ((ChatSession.initiator_id == recipient.id) & (ChatSession.recipient_id == current_user.id))
        ).filter(
            (ChatSession.is_active == True) & 
            (ChatSession.expires_at > datetime.datetime.utcnow())
        ).first()
        
        if existing_session:
            # Odśwież sesję - przedłuż jej ważność
            existing_session.refresh_session()
            
            return jsonify({
                'status': 'success', 
                'message': 'Sesja istnieje', 
                'session_id': existing_session.id,
                'is_new': False
            })
        
        # Jeśli nie istnieje sesja, a metoda to GET, zwróć błąd
        if request.method == 'GET':
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        # Jeśli metoda to POST, utwórz nową sesję
        new_session = ChatSession.create_session(current_user.id, recipient.id)
        
        return jsonify({
            'status': 'success', 
            'message': 'Utworzono nową sesję', 
            'session_id': new_session.id,
            'is_new': True
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_api.route('/messages/<int:session_id>', methods=['GET'])
@login_required
def get_messages(session_id):
    """Pobiera wiadomości z określonej sesji"""
    try:
        # Sprawdź, czy sesja istnieje i użytkownik ma do niej dostęp
        session = ChatSession.query.get(session_id)
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do sesji'}), 403
            
        # Sprawdź czy sesja jest aktywna
        if not session.is_active or session.expires_at < datetime.datetime.utcnow():
            return jsonify({'status': 'error', 'message': 'Sesja wygasła'}), 400
            
        # Pobierz wiadomości
        messages = Message.query.filter_by(session_id=session_id).order_by(Message.timestamp).all()
        
        # Przygotuj dane wiadomości do odpowiedzi JSON
        messages_data = []
        for msg in messages:
            messages_data.append({
                'id': msg.id,
                'sender_id': msg.sender_id,
                'content': msg.content,  # Zaszyfrowana zawartość
                'iv': msg.iv,  # Wektor inicjalizacyjny
                'timestamp': msg.timestamp.isoformat(),
                'read': msg.read,
                'is_mine': msg.sender_id == current_user.id
            })
            
        # Aktualizuj czas ostatniej aktywności sesji
        session.last_activity = datetime.datetime.utcnow()
        db.session.commit()
            
        return jsonify({
            'status': 'success',
            'session_id': session_id,
            'messages': messages_data
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_api.route('/send', methods=['POST'])
@login_required
def send_message():
    """Wysyła nową zaszyfrowaną wiadomość"""
    try:
        data = request.get_json()
        
        session_id = data.get('session_id')
        content = data.get('content')  # Zaszyfrowana treść
        iv = data.get('iv')  # Wektor inicjalizacyjny
        
        # Sprawdź dane wejściowe
        if not session_id or not content:
            return jsonify({'status': 'error', 'message': 'Brak wymaganych danych'}), 400
            
        # Sprawdź sesję
        session = ChatSession.query.get(session_id)
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do sesji'}), 403
            
        # Sprawdź czy sesja jest aktywna
        if not session.is_active or session.expires_at < datetime.datetime.utcnow():
            return jsonify({'status': 'error', 'message': 'Sesja wygasła'}), 400
        
        # Utwórz nową wiadomość
        message = Message(
            session_id=session_id,
            sender_id=current_user.id,
            content=content,
            iv=iv or ''  # Jeśli brak, użyj pustego stringa
        )
        
        # Dodaj do bazy i zatwiedź
        db.session.add(message)
        
        # Odśwież sesję
        session.last_activity = datetime.datetime.utcnow()
        session.refresh_session()
        
        # Zatwiedź transakcję
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message_id': message.id,
            'timestamp': message.timestamp.isoformat()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_api.route('/mark-read/<int:session_id>', methods=['POST'])
@login_required
def mark_messages_read(session_id):
    """Oznacza wszystkie wiadomości w sesji jako przeczytane"""
    try:
        # Sprawdź sesję
        session = ChatSession.query.get(session_id)
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do sesji'}), 403
            
        # Znajdź wszystkie nieprzeczytane wiadomości od innych użytkowników
        unread_messages = Message.query.filter(
            Message.session_id == session_id,
            Message.sender_id != current_user.id,
            Message.read == False
        ).all()
        
        # Oznacz wiadomości jako przeczytane
        count = 0
        for message in unread_messages:
            message.read = True
            count += 1
            
        # Zapisz zmiany
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'count': count,
            'message': f'Oznaczono {count} wiadomości jako przeczytane'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_api.route('/friends', methods=['GET'])
@login_required
def get_friends():
    """Zwraca listę znajomych (użytkowników z aktywnych sesji czatu)"""
    try:
        # Pobierz aktywne sesje
        active_sessions = ChatSession.get_active_sessions(current_user.id)
        
        # Przygotuj dane odpowiedzi
        friends_data = []
        for session in active_sessions:
            # Określ drugiego użytkownika w sesji
            other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
            other_user = User.query.get(other_user_id)
            
            if other_user:
                # Policz nieprzeczytane wiadomości
                unread_count = Message.query.filter(
                    Message.session_id == session.id,
                    Message.sender_id != current_user.id,
                    Message.read == False
                ).count()
                
                friends_data.append({
                    'username': other_user.username,
                    'user_id': other_user.user_id,
                    'is_online': getattr(other_user, 'is_online', False),
                    'last_active': other_user.last_active.isoformat() if hasattr(other_user, 'last_active') else None,
                    'session_id': session.id,
                    'unread_count': unread_count
                })
        
        return jsonify({
            'status': 'success',
            'friends': friends_data
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_api.route('/delete-session/<int:session_id>', methods=['POST'])
@login_required
def delete_session(session_id):
    """Usuwa (dezaktywuje) sesję czatu"""
    try:
        # Sprawdź sesję
        session = ChatSession.query.get(session_id)
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu do sesji'}), 403
            
        # Dezaktywuj sesję
        session.invalidate()
        
        return jsonify({
            'status': 'success',
            'message': 'Sesja została usunięta'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
