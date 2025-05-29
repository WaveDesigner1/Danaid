-- Migration script for dual encryption support
-- Run this to update existing database schema

-- Add new columns to chat_session table
ALTER TABLE chat_session ADD COLUMN encrypted_keys_json TEXT;
ALTER TABLE chat_session ADD COLUMN key_generator_id INTEGER REFERENCES "user"(id);

-- Add new column to message table  
ALTER TABLE message ADD COLUMN is_encrypted BOOLEAN DEFAULT TRUE;

-- Create indexes for better performance
CREATE INDEX idx_chat_session_key_generator ON chat_session(key_generator_id);
CREATE INDEX idx_chat_session_encrypted_keys ON chat_session(encrypted_keys_json);
CREATE INDEX idx_message_encrypted ON message(is_encrypted);

-- Update existing sessions to have empty keys initially
UPDATE chat_session SET encrypted_keys_json = '{}' WHERE encrypted_keys_json IS NULL;

-- Optional: Backup old encrypted_session_key data before dropping
-- CREATE TABLE chat_session_backup AS SELECT * FROM chat_session WHERE encrypted_session_key IS NOT NULL;

-- Optional: Drop old column after confirming migration works
-- ALTER TABLE chat_session DROP COLUMN encrypted_session_key;
-- ALTER TABLE chat_session DROP COLUMN key_acknowledged;

-- Verify migration
SELECT 
    COUNT(*) as total_sessions,
    COUNT(encrypted_keys_json) as sessions_with_json_keys,
    COUNT(key_generator_id) as sessions_with_generator
FROM chat_session;
