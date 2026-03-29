from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import time
import threading

app = Flask(__name__)
# Enable CORS so your HTML file can communicate with the server locally
CORS(app) 

# Configure max upload size to 16MB (since we encode to Base64 in frontend)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

# Your Secret API Key
API_KEY = "super_secret_bridge_api_key_2024"

# ==========================================
# 1. DATABASE & AUTO-DELETE SYSTEM
# ==========================================
class SecureDatabase:
    def __init__(self, db_name="ephemeral_vault.db"):
        self.db_name = db_name
        self._init_db()
        self.cleanup_interval = 30 # Check for expired items every 30 seconds
        self._start_cleanup_daemon()

    def _init_db(self):
        with sqlite3.connect(self.db_name) as conn:
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

    def _start_cleanup_daemon(self):
        daemon = threading.Thread(target=self._auto_delete_worker, daemon=True)
        daemon.start()

    def _auto_delete_worker(self):
        while True:
            try:
                current_time = time.time()
                with sqlite3.connect(self.db_name) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM vault WHERE expiry_time <= ?", (current_time,))
                    expired_count = cursor.fetchone()[0]
                    
                    if expired_count > 0:
                        cursor.execute("DELETE FROM vault WHERE expiry_time <= ?", (current_time,))
                        conn.commit()
                        print(f"[Daemon] Burned {expired_count} expired payload(s).")
            except Exception as e:
                print(f"[Daemon] Error: {e}")
            time.sleep(self.cleanup_interval)

    def store_payload(self, record_id, ciphertext, data_type, lifespan_minutes=10):
        expiry_time = time.time() + (lifespan_minutes * 60)
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO vault (id, ciphertext, data_type, expiry_time) VALUES (?, ?, ?, ?)",
                    (record_id, ciphertext, data_type, expiry_time)
                )
                conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False # ID already exists

    def retrieve_and_burn_payload(self, record_id):
        current_time = time.time()
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ciphertext, data_type FROM vault WHERE id = ? AND expiry_time > ?",
                (record_id, current_time)
            )
            result = cursor.fetchone()
            
            if result:
                # BURN AFTER READING
                cursor.execute("DELETE FROM vault WHERE id = ?", (record_id,))
                conn.commit()
                return {"ciphertext": result[0], "data_type": result[1]}
            return None

db = SecureDatabase()

# ==========================================
# 2. API ENDPOINTS
# ==========================================
def require_api_key(func):
    """Decorator to enforce API Key checking"""
    def wrapper(*args, **kwargs):
        provided_key = request.headers.get("X-API-Key")
        if provided_key != API_KEY:
            return jsonify({"error": "Unauthorized. Invalid API Key."}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@app.route('/api/store', methods=['POST'])
@require_api_key
def store_data():
    data = request.json
    record_id = data.get("id")
    ciphertext = data.get("ciphertext")
    data_type = data.get("data_type")

    if not all([record_id, ciphertext, data_type]):
        return jsonify({"error": "Missing required fields."}), 400

    success = db.store_payload(record_id, ciphertext, data_type, lifespan_minutes=10)
    
    if success:
        return jsonify({"message": "Payload secured successfully."}), 201
    else:
        return jsonify({"error": "This 6-digit code is already in use right now. Try another."}), 409

@app.route('/api/retrieve/<record_id>', methods=['GET'])
@require_api_key
def retrieve_data(record_id):
    payload = db.retrieve_and_burn_payload(record_id)
    if payload:
        return jsonify(payload), 200
    else:
        return jsonify({"error": "Payload not found, has expired, or was already burned."}), 404

if __name__ == '__main__':
    print("--- SecretBridge Server Running on http://127.0.0.1:5000 ---")
    app.run(port=5000, debug=True)
