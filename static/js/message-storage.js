/**
 * message-storage.js - Local Message Storage for Forward Secrecy
 * Stores decrypted messages locally for offline access and better UX
 */

class MessageStorage {
    constructor() {
        this.dbName = 'DanaidChatStorage';
        this.dbVersion = 1;
        this.db = null;
        this.storeName = 'decryptedMessages';
        this.isInitialized = false;
    }

    async init() {
        if (this.isInitialized) return true;

        try {
            await this.openDatabase();
            this.isInitialized = true;
            console.log("✅ MessageStorage initialized");
            return true;
        } catch (error) {
            console.error("❌ MessageStorage initialization failed:", error);
            return false;
        }
    }

    openDatabase() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.dbVersion);

            request.onerror = () => {
                reject(new Error('Failed to open IndexedDB'));
            };

            request.onsuccess = (event) => {
                this.db = event.target.result;
                resolve(this.db);
            };

            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Create object store for messages
                if (!db.objectStoreNames.contains(this.storeName)) {
                    const store = db.createObjectStore(this.storeName, { 
                        keyPath: 'id',
                        autoIncrement: false
                    });
                    
                    // Create indexes
                    store.createIndex('sessionToken', 'sessionToken', { unique: false });
                    store.createIndex('timestamp', 'timestamp', { unique: false });
                    store.createIndex('senderId', 'senderId', { unique: false });
                    
                    console.log("📦 Created IndexedDB object store");
                }
            };
        });
    }

    // ============= CORE STORAGE METHODS =============

    async storeMessage(sessionToken, message) {
        if (!this.isInitialized) {
            console.warn("MessageStorage not initialized, using fallback");
            return this.fallbackStore(sessionToken, message);
        }

        try {
            const transaction = this.db.transaction([this.storeName], 'readwrite');
            const store = transaction.objectStore(this.storeName);

            const messageRecord = {
                id: `${sessionToken}_${message.id}`,
                messageId: message.id,
                sessionToken: sessionToken,
                senderId: message.sender_id,
                content: message.content,
                timestamp: message.timestamp,
                isDecrypted: true,
                forwardSecrecy: message.forwardSecrecy || false,
                messageNumber: message.messageNumber || null,
                storedAt: Date.now()
            };

            await new Promise((resolve, reject) => {
                const request = store.put(messageRecord);
                request.onsuccess = () => resolve();
                request.onerror = () => reject(request.error);
            });

            console.log(`💾 Message stored in IndexedDB: ${sessionToken.slice(0, 8)}...`);
            return true;

        } catch (error) {
            console.error("❌ Failed to store message in IndexedDB:", error);
            return this.fallbackStore(sessionToken, message);
        }
    }

    async getMessages(sessionToken, limit = 100) {
        if (!this.isInitialized) {
            return this.fallbackGet(sessionToken);
        }

        try {
            const transaction = this.db.transaction([this.storeName], 'readonly');
            const store = transaction.objectStore(this.storeName);
            const index = store.index('sessionToken');

            const messages = await new Promise((resolve, reject) => {
                const messages = [];
                const request = index.openCursor(IDBKeyRange.only(sessionToken));

                request.onsuccess = (event) => {
                    const cursor = event.target.result;
                    if (cursor) {
                        messages.push(cursor.value);
                        cursor.continue();
                    } else {
                        resolve(messages);
                    }
                };

                request.onerror = () => reject(request.error);
            });

            // Sort by timestamp and limit
            const sortedMessages = messages
                .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
                .slice(-limit);

            console.log(`📱 Retrieved ${sortedMessages.length} messages from IndexedDB`);
            return sortedMessages.map(record => ({
                id: record.messageId,
                sender_id: record.senderId,
                content: record.content,
                timestamp: record.timestamp,
                forwardSecrecy: record.forwardSecrecy,
                messageNumber: record.messageNumber
            }));

        } catch (error) {
            console.error("❌ Failed to get messages from IndexedDB:", error);
            return this.fallbackGet(sessionToken);
        }
    }

    async clearSession(sessionToken) {
        if (!this.isInitialized) {
            this.fallbackClear(sessionToken);
            return;
        }

        try {
            const transaction = this.db.transaction([this.storeName], 'readwrite');
            const store = transaction.objectStore(this.storeName);
            const index = store.index('sessionToken');

            await new Promise((resolve, reject) => {
                const request = index.openCursor(IDBKeyRange.only(sessionToken));

                request.onsuccess = (event) => {
                    const cursor = event.target.result;
                    if (cursor) {
                        cursor.delete();
                        cursor.continue();
                    } else {
                        resolve();
                    }
                };

                request.onerror = () => reject(request.error);
            });

            console.log(`🧹 Cleared session ${sessionToken.slice(0, 8)}... from IndexedDB`);

        } catch (error) {
            console.error("❌ Failed to clear session from IndexedDB:", error);
            this.fallbackClear(sessionToken);
        }
    }

    async clearOldMessages(maxAge = 7 * 24 * 60 * 60 * 1000) { // 7 days
        if (!this.isInitialized) return;

        try {
            const cutoffTime = Date.now() - maxAge;
            const transaction = this.db.transaction([this.storeName], 'readwrite');
            const store = transaction.objectStore(this.storeName);

            let deletedCount = 0;

            await new Promise((resolve, reject) => {
                const request = store.openCursor();

                request.onsuccess = (event) => {
                    const cursor = event.target.result;
                    if (cursor) {
                        const record = cursor.value;
                        if (record.storedAt < cutoffTime) {
                            cursor.delete();
                            deletedCount++;
                        }
                        cursor.continue();
                    } else {
                        resolve();
                    }
                };

                request.onerror = () => reject(request.error);
            });

            console.log(`🧹 Cleaned up ${deletedCount} old messages from IndexedDB`);
            return deletedCount;

        } catch (error) {
            console.error("❌ Failed to clean old messages:", error);
            return 0;
        }
    }

    // ============= FALLBACK TO SESSIONSTORAGE =============

    fallbackStore(sessionToken, message) {
        try {
            const key = `danaid_messages_${sessionToken}`;
            const existing = JSON.parse(sessionStorage.getItem(key) || '[]');
            
            // Remove duplicates
            const filtered = existing.filter(m => m.id !== message.id);
            filtered.push(message);
            
            // Keep only last 50 messages
            if (filtered.length > 50) {
                filtered.splice(0, filtered.length - 50);
            }
            
            sessionStorage.setItem(key, JSON.stringify(filtered));
            console.log("💾 Message stored in sessionStorage (fallback)");
            return true;

        } catch (error) {
            console.error("❌ Fallback storage failed:", error);
            return false;
        }
    }

    fallbackGet(sessionToken) {
        try {
            const key = `danaid_messages_${sessionToken}`;
            const stored = sessionStorage.getItem(key);
            return stored ? JSON.parse(stored) : [];
        } catch (error) {
            console.error("❌ Fallback retrieval failed:", error);
            return [];
        }
    }

    fallbackClear(sessionToken) {
        try {
            const key = `danaid_messages_${sessionToken}`;
            sessionStorage.removeItem(key);
            console.log("🧹 Session cleared from sessionStorage (fallback)");
        } catch (error) {
            console.error("❌ Fallback clear failed:", error);
        }
    }

    // ============= UTILITY METHODS =============

    async getStorageStats() {
        if (!this.isInitialized) {
            return { type: 'sessionStorage', error: 'IndexedDB not available' };
        }

        try {
            const transaction = this.db.transaction([this.storeName], 'readonly');
            const store = transaction.objectStore(this.storeName);

            const count = await new Promise((resolve, reject) => {
                const request = store.count();
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(request.error);
            });

            // Estimate storage usage
            const estimate = await navigator.storage?.estimate?.() || {};

            return {
                type: 'IndexedDB',
                messageCount: count,
                quota: estimate.quota || 'unknown',
                usage: estimate.usage || 'unknown',
                usagePercent: estimate.quota ? 
                    Math.round((estimate.usage / estimate.quota) * 100) : 'unknown'
            };

        } catch (error) {
            console.error("❌ Failed to get storage stats:", error);
            return { type: 'IndexedDB', error: error.message };
        }
    }

    async isAvailable() {
        return 'indexedDB' in
