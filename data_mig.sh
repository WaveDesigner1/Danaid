sqlite3 users.db << 'EOF'
-- Tworzenie tabeli chat_session dla sesji czatu
CREATE TABLE IF NOT EXISTS chat_session (
    id INTEGER PRIMARY KEY,
    initiator_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    session_token VARCHAR(100) NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY (initiator_id) REFERENCES user (id),
    FOREIGN KEY (recipient_id) REFERENCES user (id)
);

-- Tworzenie tabeli message dla wiadomości
CREATE TABLE IF NOT EXISTS message (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    encrypted_data TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_delivered BOOLEAN DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES chat_session (id),
    FOREIGN KEY (sender_id) REFERENCES user (id)
);

-- Indeksy dla zwiększenia wydajności
CREATE INDEX IF NOT EXISTS idx_session_token ON chat_session(session_token);
CREATE INDEX IF NOT EXISTS idx_session_users ON chat_session(initiator_id, recipient_id);
CREATE INDEX IF NOT EXISTS idx_message_session ON message(session_id);
CREATE INDEX IF NOT EXISTS idx_message_sender ON message(sender_id);
EOF

echo "Migracja bazy danych zakończona pomyślnie!"
