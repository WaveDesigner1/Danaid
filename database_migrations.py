"""
Database migrations for E2EE chat functionality
"""

import logging
from datetime import datetime
from flask import Flask
from models import db, User, ChatSession, Message
from sqlalchemy import inspect, text

logger = logging.getLogger(__name__)

def apply_migrations(app: Flask) -> None:
    """Apply database migrations for E2EE chat"""
    with app.app_context():
        try:
            logger.info("Starting E2EE chat database migrations")
            
            # Get database inspector
            inspector = inspect(db.engine)
            
            # Apply migrations for new tables
            create_friends_tables(inspector)
            
            # Apply migrations for existing tables
            add_header_column_to_messages(inspector)
            
            logger.info("Database migrations completed successfully")
        except Exception as e:
            logger.error(f"Error during database migrations: {e}")
            raise

def create_friends_tables(inspector) -> None:
    """Create tables for friends functionality if they don't exist"""
    tables = inspector.get_table_names()
    
    # Create FriendRequest table if it doesn't exist
    if 'friend_request' not in tables:
        logger.info("Creating 'friend_request' table")
        
        try:
            db.session.execute(text("""
                CREATE TABLE friend_request (
                    id SERIAL PRIMARY KEY,
                    from_user_id INTEGER NOT NULL REFERENCES "user" (id),
                    to_user_id INTEGER NOT NULL REFERENCES "user" (id),
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (from_user_id, to_user_id)
                )
            """))
            
            # Create indexes
            db.session.execute(text("""
                CREATE INDEX idx_friend_request_from_user_id ON friend_request (from_user_id);
                CREATE INDEX idx_friend_request_to_user_id ON friend_request (to_user_id);
                CREATE INDEX idx_friend_request_status ON friend_request (status);
            """))
            
            db.session.commit()
            logger.info("Created 'friend_request' table successfully")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating 'friend_request' table: {e}")
            raise
    
    # Create Friend table if it doesn't exist
    if 'friend' not in tables:
        logger.info("Creating 'friend' table")
        
        try:
            db.session.execute(text("""
                CREATE TABLE friend (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES "user" (id),
                    friend_id INTEGER NOT NULL REFERENCES "user" (id),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (user_id, friend_id)
                )
            """))
            
            # Create indexes
            db.session.execute(text("""
                CREATE INDEX idx_friend_user_id ON friend (user_id);
                CREATE INDEX idx_friend_friend_id ON friend (friend_id);
            """))
            
            db.session.commit()
            logger.info("Created 'friend' table successfully")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating 'friend' table: {e}")
            raise

def add_header_column_to_messages(inspector) -> None:
    """Add header column to messages table for Double Ratchet algorithm"""
    columns = {c['name'] for c in inspector.get_columns('message')}
    
    # Add header column if it doesn't exist
    if 'header' not in columns:
        logger.info("Adding 'header' column to 'message' table")
        
        try:
            db.session.execute(text('ALTER TABLE "message" ADD COLUMN header TEXT'))
            db.session.commit()
            logger.info("Added 'header' column to 'message' table successfully")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error adding 'header' column to 'message' table: {e}")
            raise

# Define new models for friends functionality
class Friend(db.Model):
    """Friends relationship model"""
    __tablename__ = 'friend'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'friend_id', name='uq_friend_user_friend'),
    )
    
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('friends', lazy='dynamic'))
    friend = db.relationship('User', foreign_keys=[friend_id], backref=db.backref('friended_by', lazy='dynamic'))
    
    def __repr__(self):
        return f'<Friend {self.user_id} -> {self.friend_id}>'

class FriendRequest(db.Model):
    """Friend request model"""
    __tablename__ = 'friend_request'
    
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)  # 'pending', 'accepted', 'rejected'
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('from_user_id', 'to_user_id', name='uq_request_from_to'),
    )
    
    from_user = db.relationship('User', foreign_keys=[from_user_id], backref=db.backref('sent_requests', lazy='dynamic'))
    to_user = db.relationship('User', foreign_keys=[to_user_id], backref=db.backref('received_requests', lazy='dynamic'))
    
    def __repr__(self):
        return f'<FriendRequest {self.from_user_id} -> {self.to_user_id} [{self.status}]>'

# Update existing models
def update_message_model():
    """Update the Message model with header field for Double Ratchet"""
    if not hasattr(Message, 'header'):
        Message.header = db.Column(db.Text, nullable=True)
