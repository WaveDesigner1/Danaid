"""
Database migrations for E2EE chat functionality
"""

import logging
from datetime import datetime
from flask import Flask
from models import db, User, ChatSession, Message, Friend, FriendRequest
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
    
    # Sprawdź, czy tabele istnieją i stwórz je używając SQLAlchemy ORM
    if 'friend_request' not in tables:
        logger.info("Creating 'friend_request' table using model")
        # Wykorzystujemy fakt, że model jest już zaimportowany (from models import)
        FriendRequest.__table__.create(db.engine)
        logger.info("Created 'friend_request' table successfully")
    
    if 'friend' not in tables:
        logger.info("Creating 'friend' table using model")
        # Wykorzystujemy fakt, że model jest już zaimportowany (from models import)
        Friend.__table__.create(db.engine)
        logger.info("Created 'friend' table successfully")
    
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

