"""
chat.py - Zunifikowany moduł czatu z naprawioną funkcjonalnością real-time
NAPRAWIONO: Socket.IO integration, friend requests, message broadcasting, KEY EXCHANGE
NAPRAWIONO: Endpoint get_key zwracał "ACK" zamiast prawdziwego klucza
"""
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from models import User, ChatSession, Message, db, Friend, FriendRequest
import datetime
import secrets
import string
import logging

logger = logging.getLogger(__name__)
chat_bp = Blueprint('chat', __name__)

# === VIEWS ===
@chat_bp.route('/chat')
@login_required
def chat():
    """Główna strona czatu"""
    return render_template('chat.html')

# === HELPER FUNCTIONS ===
def _generate_session_token():
    """Generuje token sesji"""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))

def _find_or_create_session(recipient_id):
    """Znajduje lub tworzy sesję czatu"""
    # Sprawdź istniejącą sesję
    existing = ChatSession.query.filter(
        ((ChatSession.initiator_id == current_user.id) & (ChatSession.recipient_id == recipient_id)) |
        ((ChatSession.initiator_id == recipient_id) & (ChatSession.recipient_id == current_user.id))
    ).filter(
        ChatSession.is_active == True, 
        ChatSession.expires_at > datetime.datetime.utcnow()
    ).first()
    
    if existing:
        # Odśwież sesję
        existing.last_activity = datetime.datetime.utcnow()
        existing.expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=30)
        db.session.commit()
        return existing
    
    # Utwórz nową sesję
    new_session = ChatSession(
        session_token=_generate_session_token(),
        initiator_id=current_user.id,
        recipient_id=recipient_id,
        created_at=datetime.datetime.utcnow(),
        last_activity=datetime.datetime.utcnow(),
        expires_at=datetime.datetime.utcnow() + datetime.timedelta(days=30),
        is_active=True
    )
    db.session.add(new_session)
    db.session.commit()
    return new_session

# === USER API ===
@chat_bp.route('/api/user/<user_id>/public_key')
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

@chat_bp.route('/api/online_users')
@login_required
def get_online_users():
    """Lista użytkowników online"""
    try:
        if hasattr(User, 'is_online'):
            online_users = User.query.filter(
                User.is_online == True, 
                User.id != current_user.id
            ).all()
            return jsonify({
                'status': 'success',
                'online_users': [{'id': u.id, 'user_id': u.user_id, 'username': u.username} for u in online_users]
            })
        return jsonify({'status': 'success', 'online_users': []})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# === FRIENDS API ===
@chat_bp.route('/api/friends')
@login_required
def get_friends():
    """Lista znajomych użytkownika"""
    try:
        friends = current_user.get_friends()
        friends_list = [{
            'id': friend.id,
            'user_id': friend.user_id,
            'username': friend.username,
            'is_online': getattr(friend, 'is_online', False)
        } for friend in friends]
        return jsonify({'status': 'success', 'friends': friends_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/friend_requests', methods=['POST'])
@login_required
def send_friend_request():
    """Wysyła zaproszenie do znajomych"""
    try:
        data = request.get_json()
        username = data.get('username')
        
        if not username:
            return jsonify({'status': 'error', 'message': 'Username required'}), 400
            
        # Find target user
        target_user = User.query.filter_by(username=username).first()
        if not target_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
            
        if target_user.id == current_user.id:
            return jsonify({'status': 'error', 'message': 'Cannot add yourself'}), 400
            
        # Check if already friends
        if current_user.is_friend_with(target_user.id):
            return jsonify({'status': 'error', 'message': 'Already friends'}), 400
            
        # Check if request already exists
        existing = FriendRequest.query.filter_by(
            from_user_id=current_user.id,
            to_user_id=target_user.id,
            status='pending'
        ).first()
        
        if existing:
            return jsonify({'status': 'error', 'message': 'Request already sent'}), 400
            
        # Create friend request
        friend_request = FriendRequest(
            from_user_id=current_user.id,
            to_user_id=target_user.id,
            status='pending'
        )
        db.session.add(friend_request)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Friend request sent'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/friend_requests/pending')
@login_required
def get_pending_requests():
    """Lista oczekujących zaproszeń"""
    try:
        requests = FriendRequest.query.filter_by(
            to_user_id=current_user.id,
            status='pending'
        ).all()
        
        requests_list = []
        for req in requests:
            sender = User.query.get(req.from_user_id)
            requests_list.append({
                'id': req.id,
                'sender_id': sender.user_id,
                'username': sender.username,
                'created_at': req.created_at.isoformat()
            })
        
        return jsonify({'status': 'success', 'requests': requests_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/friend_requests/<int:request_id>/accept', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    """Akceptuje zaproszenie"""
    try:
        friend_request = FriendRequest.query.filter_by(
            id=request_id,
            to_user_id=current_user.id,
            status='pending'
        ).first()
        
        if not friend_request:
            return jsonify({'status': 'error', 'message': 'Zaproszenie nie znalezione'}), 404
            
        # Aktualizuj status
        friend_request.status = 'accepted'
        friend_request.updated_at = datetime.datetime.utcnow()
        
        # Dodaj znajomość (obie strony)
        friend1 = Friend(user_id=current_user.id, friend_id=friend_request.from_user_id)
        friend2 = Friend(user_id=friend_request.from_user_id, friend_id=current_user.id)
        
        db.session.add(friend1)
        db.session.add(friend2)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Zaproszenie zaakceptowane'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/friend_requests/<int:request_id>/reject', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    """Odrzuca zaproszenie"""
    try:
        friend_request = FriendRequest.query.filter_by(
            id=request_id,
            to_user_id=current_user.id,
            status='pending'
        ).first()
        
        if not friend_request:
            return jsonify({'status': 'error', 'message': 'Zaproszenie nie znalezione'}), 404
            
        friend_request.status = 'rejected'
        friend_request.updated_at = datetime.datetime.utcnow()
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Zaproszenie odrzucone'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# === SESSIONS API ===
@chat_bp.route('/api/session/init', methods=['POST'])
@login_required
def init_chat_session():
    """Inicjuje sesję czatu z automatycznym generowaniem klucza"""
    try:
        data = request.get_json()
        recipient_id = data.get('recipient_id')
        
        if not recipient_id:
            return jsonify({'status': 'error', 'message': 'Brak ID adresata'}), 400
            
        recipient = User.query.filter_by(user_id=recipient_id).first()
        if not recipient:
            return jsonify({'status': 'error', 'message': 'Adresat nie istnieje'}), 404
            
        session = _find_or_create_session(recipient.id)
        print(f"🔑 Session initialized: {session.session_token[:8]} - INITIATOR: {current_user.id}")
        
        # === AUTOMATYCZNE GENEROWANIE KLUCZA PRZEZ INITIATORA ===
        is_initiator = (current_user.id == session.initiator_id)
        
        if is_initiator and not session.encrypted_session_key:
            print(f"🔑 INITIATOR {current_user.id} - Auto-generating session key...")
            
            try:
                # 1. Wygeneruj klucz AES sesji (po stronie serwera)
                import secrets
                import base64
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.primitives import serialization, hashes
                from cryptography.hazmat.primitives.asymmetric import rsa, padding
                
                # Generuj losowy 32-bajtowy klucz AES
                aes_key = secrets.token_bytes(32)  # 256-bit AES key
                aes_key_base64 = base64.b64encode(aes_key).decode('utf-8')
                print(f"🔑 Generated AES key, length: {len(aes_key_base64)}")
                
                # 2. Pobierz klucz publiczny odbiorcy
                recipient_public_key_pem = recipient.public_key
                if not recipient_public_key_pem:
                    raise Exception("Recipient has no public key")
                
                # Import klucza publicznego
                from cryptography.hazmat.primitives import serialization
                public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode('utf-8'))
                print(f"🔑 Loaded recipient's public key")
                
                # 3. Zaszyfruj klucz AES kluczem publicznym odbiorcy (RSA-OAEP)
                encrypted_aes_key = public_key.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Convert to base64 for storage
                encrypted_key_base64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
                print(f"🔑 Encrypted session key with RSA, length: {len(encrypted_key_base64)}")
                
                # 4. Zapisz zaszyfrowany klucz w sesji
                session.encrypted_session_key = encrypted_key_base64
                session.key_created_at = datetime.datetime.utcnow()
                session.key_acknowledged = False
                db.session.commit()
                
                print(f"✅ INITIATOR {current_user.id}: Auto-generated and stored session key for {session.session_token[:8]}")
                
            except Exception as key_error:
                print(f"❌ Auto key generation failed: {key_error}")
                # Don't fail the session creation, just log the error
                session.encrypted_session_key = None
        
        elif not is_initiator:
            print(f"🔓 RECIPIENT {current_user.id} - will retrieve key from initiator")
        
        else:
            print(f"🔑 Session key already exists: {bool(session.encrypted_session_key)}")
        
        return jsonify({
            'status': 'success',
            'message': 'Sesja zainicjalizowana',
            'session': {
                'id': session.id,
                'token': session.session_token,
                'expires_at': session.expires_at.isoformat(),
                'initiator_id': session.initiator_id,
                'recipient_id': session.recipient_id,
                'has_key': session.encrypted_session_key is not None,
                'key_acknowledged': session.key_acknowledged,
                'auto_key_generated': is_initiator and session.encrypted_session_key is not None,
                'other_user': {
                    'id': recipient.id,
                    'user_id': recipient.user_id,
                    'username': recipient.username,
                    'is_online': getattr(recipient, 'is_online', False)
                }
            }
        })
    except Exception as e:
        db.session.rollback()
        print(f"❌ Session initialization error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/sessions/active')
@login_required
def get_active_sessions():
    """Lista aktywnych sesji"""
    try:
        sessions = ChatSession.query.filter(
            ((ChatSession.initiator_id == current_user.id) | (ChatSession.recipient_id == current_user.id)),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.datetime.utcnow()
        ).all()
        
        session_list = []
        for session in sessions:
            other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
            other_user = User.query.get(other_user_id)
            
            unread_count = Message.query.filter_by(
                session_id=session.id,
                sender_id=other_user_id,
                read=False
            ).count()
            
            session_list.append({
                'id': session.id,
                'token': session.session_token,
                'expires_at': session.expires_at.isoformat(),
                'last_activity': session.last_activity.isoformat(),
                'has_key': session.encrypted_session_key is not None,
                'key_acknowledged': session.key_acknowledged,
                'other_user': {
                    'id': other_user.id,
                    'user_id': other_user.user_id,
                    'username': other_user.username,
                    'is_online': getattr(other_user, 'is_online', False)
                },
                'unread_count': unread_count
            })
        
        return jsonify({'status': 'success', 'sessions': session_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# === NAPRAWIONY KEY EXCHANGE ===
@chat_bp.route('/api/session/<session_token>/exchange_key', methods=['POST'])
@login_required
def exchange_session_key(session_token):
    """Naprawiona wymiana klucza sesji - koordynacja między użytkownikami"""
    try:
        data = request.get_json()
        encrypted_key = data.get('encrypted_key')
        
        if not encrypted_key:
            return jsonify({'status': 'error', 'message': 'Brak klucza'}), 400
            
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu'}), 403
        
        print(f"🔑 Key exchange request from user {current_user.id} for session {session_token[:8]}...")
        print(f"🔑 Encrypted key data: {encrypted_key[:50]}...")
        
        # === NAPRAWIONA LOGIKA: ROZRÓŻNIENIE ACK od KLUCZA ===
        is_initiator = (current_user.id == session.initiator_id)
        
        if encrypted_key == 'ACK':
            # === RECIPIENT POTWIERDZA ODBIÓR KLUCZA ===
            print(f"🔓 RECIPIENT {current_user.id} acknowledging key receipt for session {session_token[:8]}")
            
            if is_initiator:
                return jsonify({'status': 'error', 'message': 'Initiator cannot send ACK'}), 400
            
            # Oznacz że klucz został potwierdzony
            session.key_acknowledged = True
            session.last_activity = datetime.datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'status': 'success', 
                'message': 'Key receipt acknowledged'
            })
            
        else:
            # === INITIATOR WYSYŁA ZASZYFROWANY KLUCZ ===
            print(f"🔑 INITIATOR {current_user.id} sending encrypted key for session {session_token[:8]}")
            print(f"🔑 Encrypted key length: {len(encrypted_key)}")
            
            if not is_initiator:
                return jsonify({'status': 'error', 'message': 'Only initiator can send encrypted key'}), 403
            
            # Walidacja klucza - powinien być długi (RSA 2048-bit = ~344 znaki base64)
            if len(encrypted_key) < 100:
                print(f"❌ Key too short: {len(encrypted_key)} chars")
                return jsonify({
                    'status': 'error', 
                    'message': f'Invalid key length: {len(encrypted_key)} (expected >100)'
                }), 400
            
            # Sprawdź czy to prawidłowy base64
            import base64
            try:
                base64.b64decode(encrypted_key)
            except Exception:
                return jsonify({
                    'status': 'error', 
                    'message': 'Invalid base64 format'
                }), 400
            
            # Zapisz zaszyfrowany klucz
            session.encrypted_session_key = encrypted_key
            session.last_activity = datetime.datetime.utcnow()
            session.key_acknowledged = False  # Resetuj potwierdzenie
            db.session.commit()
            
            print(f"✅ INITIATOR: Encrypted session key stored for {session_token[:8]} (length: {len(encrypted_key)})")
            
            return jsonify({
                'status': 'success', 
                'message': 'Encrypted session key stored'
            })
            
    except Exception as e:
        db.session.rollback()
        print(f"❌ Key exchange error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# === NAPRAWIONY ENDPOINT: POBIERZ KLUCZ SESJI ===
@chat_bp.route('/api/session/<session_token>/get_key', methods=['GET'])
@login_required
def get_session_key(session_token):
    """NAPRAWIONY: Pobiera zaszyfrowany klucz sesji dla odbiorcy"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            print(f"❌ Session not found: {session_token[:8]}")
            return jsonify({'status': 'error', 'message': 'Session not found'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            print(f"❌ Access denied for user {current_user.id} to session {session_token[:8]}")
            return jsonify({'status': 'error', 'message': 'Access denied'}), 403
        
        is_recipient = (current_user.id == session.recipient_id)
        
        print(f"🔍 Get key request from {'RECIPIENT' if is_recipient else 'INITIATOR'} {current_user.id}")
        print(f"🔍 Session {session_token[:8]} - has key: {bool(session.encrypted_session_key)}")
        
        # === NAPRAWIONA LOGIKA: TYLKO RECIPIENT MOŻE POBRAĆ KLUCZ ===
        if not is_recipient:
            print(f"❌ Only recipient can get session key, user {current_user.id} is initiator")
            return jsonify({'status': 'error', 'message': 'Only recipient can get session key'}), 403
        
        # Sprawdź czy klucz istnieje i nie jest "ACK"
        if not session.encrypted_session_key or session.encrypted_session_key == 'ACK':
            print(f"⏳ Session key not ready yet for {session_token[:8]}")
            return jsonify({'status': 'waiting', 'message': 'Session key not ready yet'}), 200
        
        print(f"🔑 Serving encrypted session key for session {session_token[:8]} to user {current_user.id}")
        print(f"🔑 Key length: {len(session.encrypted_session_key)}")
        
        # Zwróć zaszyfrowany klucz
        return jsonify({
            'status': 'success',
            'encrypted_session_key': session.encrypted_session_key,
            'key_acknowledged': session.key_acknowledged,
            'initiator_id': session.initiator_id
        })
        
    except Exception as e:
        print(f"❌ Get session key error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/session/<session_token>/close', methods=['POST'])
@login_required
def close_session(session_token):
    """Zamyka sesję"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu'}), 403
            
        session.is_active = False
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Sesja zamknięta'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# === MESSAGES API ===
@chat_bp.route('/api/messages/<session_token>')
@login_required
def get_messages(session_token):
    """Pobiera wiadomości z sesji"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Sesja nie istnieje'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Brak dostępu'}), 403
            
        if not session.is_active or session.expires_at < datetime.datetime.utcnow():
            return jsonify({'status': 'error', 'message': 'Sesja wygasła'}), 401
        
        # Pobierz wiadomości
        messages = Message.query.filter_by(session_id=session.id).order_by(Message.timestamp).all()
        
        # Oznacz jako przeczytane
        other_user_id = session.recipient_id if session.initiator_id == current_user.id else session.initiator_id
        unread_messages = Message.query.filter_by(
            session_id=session.id,
            sender_id=other_user_id,
            read=False
        ).all()
        
        for msg in unread_messages:
            msg.read = True
        db.session.commit()
        
        message_list = [{
            'id': msg.id,
            'sender_id': msg.sender_id,
            'content': msg.content,
            'iv': msg.iv,
            'timestamp': msg.timestamp.isoformat(),
            'is_mine': msg.sender_id == current_user.id
        } for msg in messages]
        
        return jsonify({'status': 'success', 'messages': message_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/message/send', methods=['POST'])
@login_required
def send_message():
    """Wysyła wiadomość z real-time broadcast"""
    try:
        print("📨 Send message endpoint called")
        data = request.get_json()
        print("Request data:", data)
        
        required_fields = ['session_token', 'content', 'iv']
        
        if not data or not all(field in data for field in required_fields):
            print("❌ Brakujące dane:", data)
            return jsonify({'status': 'error', 'message': 'Brakujące dane'}), 400
            
        session_token = data.get('session_token')
        content = data.get('content')
        iv = data.get('iv')
        
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            print("❌ Nieprawidłowa sesja:", session_token)
            return jsonify({'status': 'error', 'message': 'Nieprawidłowa sesja'}), 404
            
        if not session.is_active or session.expires_at < datetime.datetime.utcnow():
            print("❌ Sesja wygasła")
            return jsonify({'status': 'error', 'message': 'Sesja wygasła'}), 401
            
        if not session.encrypted_session_key or session.encrypted_session_key == 'ACK':
            print("❌ Brak klucza sesji lub klucz nie gotowy")
            return jsonify({'status': 'error', 'message': 'Session key not ready'}), 400
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            print("❌ Brak dostępu do sesji")
            return jsonify({'status': 'error', 'message': 'Brak dostępu'}), 403
        
        print("✅ Walidacja przeszła, zapisuję wiadomość")
        
        # Zapisz wiadomość
        new_message = Message(
            session_id=session.id,
            sender_id=current_user.id,
            content=content,
            iv=iv,
            timestamp=datetime.datetime.utcnow(),
            read=False
        )
        db.session.add(new_message)
        
        # Odśwież sesję
        session.last_activity = datetime.datetime.utcnow()
        
        if not session.key_acknowledged:
            session.key_acknowledged = True
            print("✅ Klucz automatycznie potwierdzony")
            
        db.session.commit()
        print("✅ Wiadomość zapisana:", new_message.id)
        
        # 🔥 REAL-TIME BROADCAST
        try:
            socketio = getattr(current_app, 'socketio', None)
            if socketio and hasattr(socketio, 'broadcast_new_message'):
                message_data = {
                    'id': new_message.id,
                    'sender_id': current_user.id,
                    'content': content,
                    'iv': iv,
                    'timestamp': new_message.timestamp.isoformat(),
                    'is_mine': False  # For recipient
                }
                socketio.broadcast_new_message(session_token, message_data)
                print("📡 Real-time message broadcasted")
            else:
                print("⚠️ Socket.IO not available for broadcast")
        except Exception as broadcast_error:
            print(f"⚠️ Broadcast failed: {broadcast_error}")
            # Don't fail the message send if broadcast fails
        
        return jsonify({
            'status': 'success',
            'message': {
                'id': new_message.id,
                'timestamp': new_message.timestamp.isoformat()
            }
        })
    except Exception as e:
        print(f"❌ Błąd wysyłania wiadomości: {e}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@chat_bp.route('/api/messages/<session_token>/clear', methods=['DELETE'])
@login_required
def clear_session_messages(session_token):
    """Usuwa wszystkie wiadomości z sesji"""
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        
        if not session:
            return jsonify({'status': 'error', 'message': 'Session not found'}), 404
            
        if session.initiator_id != current_user.id and session.recipient_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Access denied'}), 403
        
        # Delete all messages in this session
        deleted_count = Message.query.filter_by(session_id=session.id).delete()
        db.session.commit()
        
        return jsonify({
            'status': 'success', 
            'message': f'Deleted {deleted_count} messages',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# === POLLING FALLBACK ===
@chat_bp.route('/api/polling/messages')
@login_required
def polling_messages():
    """Endpoint fallback do odbierania wiadomości poprzez polling"""
    try:
        last_id = request.args.get('last_id', 0)
        try:
            last_id = int(last_id)
        except ValueError:
            last_id = 0
        
        # Znajdź aktywne sesje
        active_sessions = ChatSession.query.filter(
            ((ChatSession.initiator_id == current_user.id) | (ChatSession.recipient_id == current_user.id)),
            ChatSession.is_active == True,
            ChatSession.expires_at > datetime.datetime.utcnow()
        ).all()
        
        session_ids = [session.id for session in active_sessions]
        
        # Pobierz nowe wiadomości
        new_messages = Message.query.filter(
            Message.session_id.in_(session_ids),
            Message.id > last_id,
            Message.sender_id != current_user.id,
            Message.read == False
        ).order_by(Message.id).all()
        
        messages = []
        max_id = last_id
        
        for msg in new_messages:
            session = next((s for s in active_sessions if s.id == msg.session_id), None)
            if session:
                max_id = max(max_id, msg.id)
                messages.append({
                    'type': 'new_message',
                    'session_token': session.session_token,
                    'message': {
                        'id': msg.id,
                        'sender_id': msg.sender_id,
                        'content': msg.content,
                        'iv': msg.iv,
                        'timestamp': msg.timestamp.isoformat(),
                        'is_mine': False
                    }
                })
        
        return jsonify({
            'status': 'success',
            'messages': messages,
            'last_id': max_id
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# === SOCKET.IO INTEGRATION ===
def init_socketio_handler(socketio):
    """Initialize Socket.IO handlers for real-time messaging"""
    print("🔌 Initializing Socket.IO handlers...")
    
    # Import the handler
    try:
        from socketio_handler import init_socketio_handler as init_handler
        # Initialize with socketio instance
        handler = init_handler(socketio)
        print("✅ Socket.IO handler from socketio_handler.py initialized")
    except Exception as e:
        print(f"⚠️ Failed to init external handler: {e}")
        handler = None
    
    # Add custom events for chat functionality
    @socketio.on('connect')
    def handle_connect():
        print(f"🔌 Client connected: {request.sid}")
        
    @socketio.on('disconnect') 
    def handle_disconnect():
        print(f"🔌 Client disconnected: {request.sid}")
        
    @socketio.on('join_session')
    def handle_join_session(data):
        """Join user to session room for real-time updates"""
        session_token = data.get('session_token')
        if session_token:
            from flask_socketio import join_room
            join_room(f"session_{session_token}")
            print(f"👤 User joined session room: {session_token[:8]}...")
    
    # Real-time message broadcasting function
    def broadcast_new_message(session_token, message_data):
        """Broadcast new message to relevant users"""
        try:
            session = ChatSession.query.filter_by(session_token=session_token).first()
            if not session:
                return
                
            # Get recipient
            sender_id = message_data.get('sender_id')
            if sender_id == session.initiator_id:
                recipient_id = session.recipient_id
            else:
                recipient_id = session.initiator_id
                
            # Send to recipient's room and session room
            socketio.emit('message', {
                'type': 'new_message',
                'session_token': session_token,
                'message': message_data
            }, room=f"user_{recipient_id}")
            
            socketio.emit('message', {
                'type': 'new_message',
                'session_token': session_token,
                'message': message_data
            }, room=f"session_{session_token}")
            
            print(f"📨 Message broadcasted to user_{recipient_id} and session_{session_token[:8]}...")
            
        except Exception as e:
            print(f"❌ Broadcast error: {e}")
    
    # Make broadcast function available globally
    socketio.broadcast_new_message = broadcast_new_message
    
    print("✅ Socket.IO handlers initialized successfully")
    return handler
