/**
 * ChatInterface - MINIMALNY DZIAŁAJĄCY
 */

// Zabezpieczenia - TYLKO JEDNA DEKLARACJA!


class ChatInterface {
  constructor(sessionManager) {
    console.log("🚀 ChatInterface konstruktor uruchomiony");
    
    this.sessionManager = sessionManager;
    this.currentSessionToken = null;
    this.currentUser = {
      id: sessionStorage.getItem('user_id'),
      username: sessionStorage.getItem('username')
    };
    this.friends = [];
    this.sessions = [];
    
    // Podstawowe elementy DOM
    this.friendsList = document.getElementById('friend-list');
    this.messagesContainer = document.getElementById('messages');
    this.messageInput = document.getElementById('message-input');
    this.sendButton = document.getElementById('send-button');
    this.chatHeader = document.getElementById('chat-header');
    
    console.log("✅ ChatInterface zainicjalizowany MINIMALNIE");
    
    // Podstawowe eventy
    this.initEvents();
  }
  
  initEvents() {
    if (this.sendButton && this.messageInput) {
      this.sendButton.addEventListener('click', () => this.sendMessage());
      
      this.messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          this.sendMessage();
        }
      });
    }
    
    console.log("✅ Podstawowe eventy skonfigurowane");
  }
  
  async sendMessage() {
    if (!this.messageInput || !this.currentSessionToken) {
      console.log("❌ Brak wymaganych elementów");
      return;
    }
    
    const content = this.messageInput.value.trim();
    if (!content) return;
    
    try {
      this.messageInput.value = '';
      
      const result = await this.sessionManager.sendMessage(this.currentSessionToken, content);
      
      if (result.status === 'success') {
        console.log('✅ Wiadomość wysłana');
        if (result.messageData) {
          this.addMessageToUI(result.messageData);
        }
      } else {
        console.error('❌ Błąd wysyłania:', result.message);
        this.messageInput.value = content;
      }
    } catch (error) {
      console.error('❌ Błąd sendMessage:', error);
      this.messageInput.value = content;
    }
  }
  
  addMessageToUI(message) {
    if (!this.messagesContainer) return;
    
    const messageDiv = document.createElement('div');
    const isSent = message.sender_id === parseInt(this.currentUser.id) || message.is_mine;
    
    messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
    messageDiv.innerHTML = `
      <div class="message-content">${message.content || '[Pusta wiadomość]'}</div>
      <div class="message-info">
        <span class="message-time">${new Date(message.timestamp).toLocaleTimeString()}</span>
      </div>
    `;
    
    // Style inline
    messageDiv.style.cssText = `
      margin-bottom: 10px;
      padding: 10px;
      border-radius: 8px;
      max-width: 70%;
      word-wrap: break-word;
      ${isSent ? 
        'background: #007bff; color: white; margin-left: auto; text-align: right;' : 
        'background: #f1f1f1; color: black; margin-right: auto; text-align: left;'
      }
    `;
    
    this.messagesContainer.appendChild(messageDiv);
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
  }
  
  showNotification(message, type = 'info') {
    console.log(`📢 [${type}]:`, message);
    
    const notification = document.createElement('div');
    notification.textContent = message;
    notification.style.cssText = `
      position: fixed; top: 20px; right: 20px; padding: 12px 20px;
      border-radius: 6px; color: white; z-index: 10000;
      background: ${type === 'success' ? '#28a745' : type === 'error' ? '#dc3545' : '#007bff'};
    `;
    
    document.body.appendChild(notification);
    setTimeout(() => notification.remove(), 3000);
  }
}

// WAŻNE: Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ChatInterface;
} else {
  window.ChatInterface = ChatInterface;
}

console.log("✅ ChatInterface MINIMALNY załadowany");
