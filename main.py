"""
main.py - Refactored Entry Point for Danaid Chat
Clean startup with SQLite support and auto-switch messaging
"""

import os
import sys
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def startup_diagnostics():
    """Startup diagnostics and file structure check"""
    print("=" * 50)
    print("DANAID CHAT - REFACTORED STARTUP")
    print("=" * 50)
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Python version: {sys.version}")
    print(f"Working directory: {os.getcwd()}")
    print(f"PORT environment: {os.environ.get('PORT', 'NOT SET (default: 8080)')}")
    print(f"Debug mode: {os.environ.get('FLASK_DEBUG', 'False')}")
    
    # Check refactored file structure
    required_files = [
        'app.py',           # Refactored app factory
        'auth.py',          # Refactored auth system
        'chat.py',          # Refactored chat with auto-switch
        'models.py',        # Clean database models
        'requirements.txt', # Updated dependencies
        '.env'              # SQLite configuration
    ]
    
    print("\nChecking refactored file structure:")
    for file in required_files:
        exists = "✅" if os.path.exists(file) else "❌"
        print(f"   {exists} {file}")
    
    # Check frontend files
    frontend_files = [
        'static/js/crypto.js',      # Unified crypto system
        'static/js/auth.js',        # Auth interface
        'static/js/chat.js',        # Chat interface with auto-switch
        'templates/chat.html',      # Main chat template
        'templates/index.html',     # Login template
        'templates/register.html'   # Registration template
    ]
    
    print("\nFrontend structure status:")
    for file in frontend_files:
        exists = "✅" if os.path.exists(file) else "❌"
        print(f"   {exists} {file}")
    
    print("\n" + "=" * 50)

def main():
    """Main entry point with error handling"""
    
    # Startup diagnostics
    startup_diagnostics()
    
    # Import app factory
    try:
        print("Importing refactored app factory...")
        from app import create_app
        logger.info("Successfully imported create_app from refactored structure")
    except ImportError as e:
        logger.error(f"Import error - check dependencies: {e}")
        print("Tip: Run 'pip install -r requirements.txt' to install dependencies")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during import: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Create application
    try:
        print("Creating Flask app with integrated Socket.IO...")
        app, socketio = create_app()
        logger.info("Flask app with Socket.IO created successfully")
        
    except Exception as e:
        logger.error(f"Error creating Flask app: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Start application
    if __name__ == "__main__":
        port = int(os.environ.get("PORT", 8080))
        debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        
        print(f"\nStarting Danaid Chat on port {port}")
        print(f"Debug mode: {debug_mode}")
        print(f"Access URL: http://localhost:{port}")
        print(f"Database: SQLite (danaid_refactored.db)")
        print("Features: Auto-switch messaging, Dual encryption, Admin panel")
        print("=" * 50)
        
        try:
            # Start with integrated Socket.IO server
            socketio.run(
                app,
                host="0.0.0.0",
                port=port,
                debug=debug_mode,
                allow_unsafe_werkzeug=True,
                log_output=False  # Reduce noise in development
            )
                
        except KeyboardInterrupt:
            print("\nGraceful shutdown initiated by user")
            logger.info("Application stopped by user")
        except Exception as e:
            logger.error(f"Error starting server: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

if __name__ == "__main__":
    main()