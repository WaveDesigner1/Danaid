/**
 * crypto.js - Minimal Legacy Compatibility Layer
 * Provides basic CryptoManager for backward compatibility
 * All actual crypto work is done by auth.js (DanaidAuthSystem)
 */

class CryptoManager {
    constructor() {
        this.isInitialized = false;
        this.version = "legacy-compat-1.0";
        console.log('🔄 CryptoManager compatibility layer loading...');
    }

    // === PODSTAWOWE METODY WYMAGANE PRZEZ STARY KOD ===
    
    async loadKeys() {
        const hasPrivateKey = !!sessionStorage.getItem('user_private_key_pem');
        if (hasPrivateKey) {
            console.log("✅ CryptoManager: Keys detected");
            return true;
        }
        console.log("ℹ️ CryptoManager: No keys found");
        return false;
    }

    hasPrivateKey() {
        return !!sessionStorage.getItem('user_private_key_pem');
    }

    clearAllKeys() {
        console.log("🧹 CryptoManager: Clearing all data");
        sessionStorage.removeItem('user_private_key_pem');
        sessionStorage.removeItem('user_id');
        sessionStorage.removeItem('username');
        sessionStorage.removeItem('is_admin');
    }

    getSecurityInfo() {
        return {
            hasPrivateKey: this.hasPrivateKey(),
            cryptoSystem: 'DanaidAuthSystem',
            version: this.version,
            webCryptoSupported: !!(window.crypto && window.crypto.subtle)
        };
    }

    optimizePerformance() {
        // Legacy method - no-op in new system
        console.log('🔧 CryptoManager: Performance optimization (legacy method)');
    }

    debugInfo() {
        return {
            system: 'Legacy compatibility layer',
            hasPrivateKey: this.hasPrivateKey(),
            authSystemLoaded: !!window.danaidAuth
        };
    }

    getPostLogoutSecurityStatus() {
        return {
            secure: !this.hasPrivateKey(),
            message: 'Security check completed'
        };
    }
}

// === AUTO-INITIALIZATION ===
if (typeof window !== 'undefined') {
    // Inicjalizuj CryptoManager automatycznie
    window.addEventListener('DOMContentLoaded', () => {
        if (!window.cryptoManager) {
            window.cryptoManager = new CryptoManager();
            window.cryptoManager.isInitialized = true;
            console.log('✅ CryptoManager auto-initialized (compatibility mode)');
        }
    });
    
    // Performance optimization - placeholder
    setInterval(() => {
        if (window.cryptoManager) {
            window.cryptoManager.optimizePerformance();
        }
    }, 300000); // Every 5 minutes
    
    // Security cleanup on page visibility change
    document.addEventListener('visibilitychange', () => {
        if (document.hidden && window.cryptoManager) {
            window.cryptoManager.optimizePerformance();
        }
    });

    // Immediate initialization if DOM already loaded
    if (document.readyState === 'loading') {
        // DOM still loading, wait for DOMContentLoaded
    } else {
        // DOM already loaded
        if (!window.cryptoManager) {
            window.cryptoManager = new CryptoManager();
            window.cryptoManager.isInitialized = true;
            console.log('✅ CryptoManager initialized immediately (compatibility mode)');
        }
    }
}

console.log('📦 CryptoManager Legacy Compatibility Layer loaded');
