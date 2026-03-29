import os
import time
import sqlite3
import threading
from flask import Flask, request, jsonify
from flask_cors import CORS

# ==========================================
# CONFIGURATION
# ==========================================
app = Flask(__name__)
CORS(app) # Enable Cross-Origin Resource Sharing for frontend communication

# Set max upload size to 50 MB (Base64 encoding increases size by ~33%)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 

# Your Secret API Key (MUST MATCH THE FRONTEND JS CONFIGURATION)
API_KEY = "super_secret_bridge_api_key_2024"
DB_NAME = "secret_bridge.db"

# ==========================================
# 1. DATABASE & AUTO-DELETE SYSTEM
# ==========================================
class SecureVaultDB:
    def __init__(self, db_file=DB_NAME):
        self.db_file = db_file
        self.cleanup_interval = 30 # Check for expired items every 30 seconds
        self._init_db()
        self._start_cleanup_daemon()

    def _init_db(self):
        """Initializes the database table if it doesn't exist."""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vault (
                    id TEXT PRIMARY KEY,
                    ciphertext TEXT NOT NULL,
                    data_type TEXT NOT NULL,
                    expiry_time REAL NOT NULL
                )
            ''')
            conn.commit()
        print(f"[Database] SQLite database '{self.db_file}' initialized.")

    def _start_cleanup_daemon(self):
        """Starts the background thread for the 10-minute auto-delete feature."""
        daemon = threading.Thread(target=self._auto_delete_worker, daemon=True)
        daemon.start()
        print("[Daemon] Auto-burn background thread started.")

    def _auto_delete_worker(self):
        """Continuously scans and deletes payloads that exceed their lifespan."""
        while True:
            try:
                current_time = time.time()
                with sqlite3.connect(self.db_file) as conn:
                    cursor = conn.cursor()
                    
                    # Check how many are expired
                    cursor.execute("SELECT COUNT(*) FROM vault WHERE expiry_time <= ?", (current_time,))
                    expired_count = cursor.fetchone()[0]
                    
                    if expired_count > 0:
                        # Delete the expired records permanently
                        cursor.execute("DELETE FROM vault WHERE expiry_time <= ?", (current_time,))
                        conn.commit()
                        print(f"[Daemon] ⚠️ Auto-Burned {expired_count} expired payload(s).")
            except Exception as e:
                print(f"[Daemon Error] {e}")
            
            # Sleep for the interval before checking again
            time.sleep(self.cleanup_interval)

    def store_payload(self, record_id, ciphertext, data_type, lifespan_minutes=10):
        """Saves a new encrypted payload with a specific expiration time."""
        expiry_time = time.time() + (lifespan_minutes * 60)
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO vault (id, ciphertext, data_type, expiry_time) VALUES (?, ?, ?, ?)",
                    (record_id, ciphertext, data_type, expiry_time)
                )
                conn.commit()
            return True
        except sqlite3.IntegrityError:
            # This happens if someone else is currently using the exact same 6-digit code ID
            return False 

    def retrieve_and_burn(self, record_id):
        """Fetches the payload and IMMEDIATELY deletes it (Burn-After-Reading)."""
        current_time = time.time()
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            # Only fetch if it hasn't expired
            cursor.execute(
                "SELECT ciphertext, data_type FROM vault WHERE id = ? AND expiry_time > ?",
                (record_id, current_time)
            )
            result = cursor.fetchone()
            
            if result:
                # Payload found. BURN IT immediately.
                cursor.execute("DELETE FROM vault WHERE id = ?", (record_id,))
                conn.commit()
                print(f"[Database] 🔥 Payload {record_id[:8]}... accessed and permanently burned.")
                return {"ciphertext": result[0], "data_type": result[1]}
            
            return None

# Initialize the Vault Database
vault_db = SecureVaultDB()

# ==========================================
# 2. API ENDPOINTS & AUTHENTICATION
# ==========================================
def require_api_key(func):
    """Decorator to enforce X-API-Key header authentication."""
    def wrapper(*args, **kwargs):
        provided_key = request.headers.get("X-API-Key")
        if not provided_key or provided_key != API_KEY:
            print(f"[API] ❌ Unauthorized access attempt. Key provided: {provided_key}")
            return jsonify({"error": "Unauthorized. Invalid or missing API Key."}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@app.route('/api/store', methods=['POST'])
@require_api_key
def api_store():
    """Endpoint to receive and store encrypted data."""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Invalid JSON payload."}), 400

        record_id = data.get("id")
        ciphertext = data.get("ciphertext")
        data_type = data.get("data_type")

        # Validate required fields
        if not all([record_id, ciphertext, data_type]):
            return jsonify({"error": "Missing required fields (id, ciphertext, data_type)."}), 400

        # Store for 10 minutes
        success = vault_db.store_payload(record_id, ciphertext, data_type, lifespan_minutes=10)
        
        if success:
            print(f"[API] 🔒 New payload stored. ID: {record_id[:8]}... Type: {data_type}")
            return jsonify({"message": "Payload secured successfully."}), 201
        else:
            return jsonify({"error": "This 6-digit code is currently in use. Please generate a different code."}), 409

    except Exception as e:
        print(f"[API Error] /api/store: {str(e)}")
        return jsonify({"error": "Internal server error during upload."}), 500

@app.route('/api/retrieve/<record_id>', methods=['GET'])
@require_api_key
def api_retrieve(record_id):
    """Endpoint to fetch and burn encrypted data."""
    try:
        payload = vault_db.retrieve_and_burn(record_id)
        
        if payload:
            return jsonify(payload), 200
        else:
            return jsonify({"error": "Payload not found. It may have expired, the code is incorrect, or it was already burned."}), 404

    except Exception as e:
        print(f"[API Error] /api/retrieve: {str(e)}")
        return jsonify({"error": "Internal server error during retrieval."}), 500

# Error handler for files that are too large
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"error": "File is too large. Maximum size is ~35MB (50MB Base64)."}), 413

# ==========================================
# 3. SERVER STARTUP
# ==========================================
if __name__ == '__main__':
    print("\n" + "="*50)
    print("🚀 SECRETBRIDGE BACKEND IS ONLINE")
    print(f"🔒 Expected API Key: {API_KEY}")
    print("🗑️  Auto-Burn Daemon: ACTIVE (10 min lifespan)")
    print("="*50 + "\n")
    
    # Run the server on all available IP addresses (0.0.0.0) on port 5000
    app.run(host='0.0.0.0', port=5000, debug=False)
