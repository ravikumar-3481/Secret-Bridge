import os
import time
import sqlite3
import threading
import uuid
import hmac
import numpy as np
from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
from werkzeug.utils import secure_filename
from sklearn.ensemble import IsolationForest

# ==========================================
# CONFIGURATION & CONSTANTS
# ==========================================
app = Flask(__name__)
CORS(app)

# Increase max upload size to 2 GB (2048 MB)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024 

# Storage Directories
VAULT_DIR = "./vault_storage"
os.makedirs(VAULT_DIR, exist_ok=True)

API_KEY = "super_secret_bridge_api_key_2024"
DB_NAME = "secret_bridge_v3.db"

# ==========================================
# 1. MACHINE LEARNING: AI SECURITY SHIELD
# ==========================================
class AISecurityShield:
    """
    Uses Machine Learning (Isolation Forest) to detect abusive upload patterns,
    DDoS attempts, and bandwidth hogs to preserve server upload speed.
    """
    def __init__(self):
        self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        self.ip_history = {}
        self._pre_train_model()
        print("[AI Shield] Isolation Forest Anomaly Detection Model Initialized.")

    def _pre_train_model(self):
        """Trains the model on dummy 'normal' traffic to establish a baseline."""
        # Features: [content_length_mb, seconds_since_last_req, total_reqs_today]
        normal_traffic = np.array([
            [5.0, 300, 1], [15.0, 1500, 2], [50.0, 3600, 1], 
            [1.0, 60, 5], [200.0, 86400, 1], [10.0, 600, 3]
        ])
        self.model.fit(normal_traffic)

    def analyze_request(self, ip_address, content_length):
        """Extracts features and predicts if the request is an anomaly/attack."""
        current_time = time.time()
        length_mb = (content_length or 0) / (1024 * 1024)

        if ip_address not in self.ip_history:
            self.ip_history[ip_address] = {'last_req': current_time, 'count': 1}
            return False # First request is fine

        history = self.ip_history[ip_address]
        time_diff = current_time - history['last_req']
        history['last_req'] = current_time
        history['count'] += 1

        # Extract live features
        features = np.array([[length_mb, time_diff, history['count']]])
        
        # Predict: 1 is normal, -1 is anomaly (e.g., sending 2GB every 2 seconds)
        prediction = self.model.predict(features)[0]
        
        if prediction == -1:
            print(f"[AI Shield] 🚨 Anomaly detected from IP: {ip_address}. Blocking to preserve bandwidth.")
            return True # Is Anomaly
        return False

ai_shield = AISecurityShield()

# ==========================================
# 2. DATABASE & DISK MANAGEMENT
# ==========================================
class SecureVaultManager:
    def __init__(self, db_file=DB_NAME):
        self.db_file = db_file
        self.cleanup_interval = 60 # Check every 60 seconds
        self._init_db()
        self._start_cleanup_daemon()

    def _init_db(self):
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            # Changed schema: We now store the file_path on disk instead of the raw ciphertext in DB
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vault_v3 (
                    id TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    data_type TEXT NOT NULL,
                    expiry_time REAL NOT NULL
                )
            ''')
            conn.commit()
        print(f"[Database] SQLite routing DB initialized.")

    def _start_cleanup_daemon(self):
        daemon = threading.Thread(target=self._auto_delete_worker, daemon=True)
        daemon.start()

    def _auto_delete_worker(self):
        """Scans DB and safely deletes files from the SSD to free up space."""
        while True:
            try:
                current_time = time.time()
                with sqlite3.connect(self.db_file) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT id, file_path FROM vault_v3 WHERE expiry_time <= ?", (current_time,))
                    expired_records = cursor.fetchall()
                    
                    for rec_id, fpath in expired_records:
                        # 1. Delete from Disk
                        if os.path.exists(fpath):
                            os.remove(fpath)
                        # 2. Delete from DB
                        cursor.execute("DELETE FROM vault_v3 WHERE id = ?", (rec_id,))
                        
                    if expired_records:
                        conn.commit()
                        print(f"[Daemon] ⚠️ Auto-Burned {len(expired_records)} expired 2GB payload(s) from SSD.")
            except Exception as e:
                print(f"[Daemon Error] {e}")
            
            time.sleep(self.cleanup_interval)

    def store_metadata(self, record_id, file_path, data_type, lifespan_minutes=10):
        expiry_time = time.time() + (lifespan_minutes * 60)
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO vault_v3 (id, file_path, data_type, expiry_time) VALUES (?, ?, ?, ?)",
                    (record_id, file_path, data_type, expiry_time)
                )
                conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False 

    def retrieve_and_burn_metadata(self, record_id):
        current_time = time.time()
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT file_path, data_type FROM vault_v3 WHERE id = ? AND expiry_time > ?",
                (record_id, current_time)
            )
            result = cursor.fetchone()
            
            if result:
                cursor.execute("DELETE FROM vault_v3 WHERE id = ?", (record_id,))
                conn.commit()
                return {"file_path": result[0], "data_type": result[1]}
            return None

vault_manager = SecureVaultManager()

# ==========================================
# 3. SECURE API ENDPOINTS
# ==========================================
def require_api_key(func):
    """Enforces authentication using constant-time comparison to prevent timing attacks."""
    def wrapper(*args, **kwargs):
        provided_key = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(provided_key, API_KEY):
            return jsonify({"error": "Unauthorized"}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@app.route('/api/store', methods=['POST'])
@require_api_key
def api_store():
    """
    High-Speed Upload Endpoint.
    Accepts Multipart FormData instead of JSON to stream directly to disk without RAM bloat.
    """
    try:
        # 1. AI Security Shield Check
        ip_addr = request.remote_addr
        content_length = request.content_length
        if ai_shield.analyze_request(ip_addr, content_length):
            return jsonify({"error": "Traffic anomaly detected. Request blocked to preserve network integrity."}), 429

        # 2. Extract Metadata
        # We expect a multipart/form-data request here for large files.
        # Fallback to JSON is possible but not recommended for 2GB files.
        record_id = request.form.get("id") or request.json.get("id") if request.is_json else request.form.get("id")
        data_type = request.form.get("data_type") or request.json.get("data_type") if request.is_json else request.form.get("data_type")
        
        if not record_id:
            return jsonify({"error": "Missing record ID."}), 400

        # Generate a secure, randomized filename for SSD storage
        secure_name = secure_filename(f"{uuid.uuid4().hex}.enc")
        file_path = os.path.join(VAULT_DIR, secure_name)

        # 3. Direct-to-Disk Streaming (The key to 2GB upload speed)
        if 'payload_file' in request.files:
            file_obj = request.files['payload_file']
            file_obj.save(file_path) # Streams directly to disk using Werkzeug
        elif request.is_json and 'ciphertext' in request.json:
            # Fallback for old frontend (Text data only, not recommended for 2GB)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(request.json['ciphertext'])
        else:
             return jsonify({"error": "No payload_file or ciphertext provided."}), 400

        # 4. Save metadata to SQLite
        success = vault_manager.store_metadata(record_id, file_path, data_type)
        
        if success:
            print(f"[API] 🔒 Secured 2GB-capable payload to disk. ID: {record_id[:8]}...")
            return jsonify({"message": "Payload secured successfully."}), 201
        else:
            os.remove(file_path) # Cleanup if DB collision
            return jsonify({"error": "This ID is currently in use."}), 409

    except Exception as e:
        print(f"[API Error] /api/store: {str(e)}")
        return jsonify({"error": "Internal server error during upload."}), 500

@app.route('/api/retrieve/<record_id>', methods=['GET'])
@require_api_key
def api_retrieve(record_id):
    """
    High-Speed Download Endpoint.
    Streams the file from disk directly to the client, then burns it.
    """
    try:
        # Fetch metadata and delete DB record
        payload = vault_manager.retrieve_and_burn_metadata(record_id)
        
        if not payload or not os.path.exists(payload['file_path']):
            return jsonify({"error": "Payload not found or already burned."}), 404

        file_path = payload['file_path']

        # Custom Generator to stream the file to the user AND delete it immediately after
        def generate_and_burn():
            try:
                with open(file_path, 'rb') as f:
                    while chunk := f.read(8192): # Stream in 8KB chunks
                        yield chunk
            finally:
                # BURN IT immediately after streaming finishes
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"[API] 🔥 File {file_path} streamed and permanently burned.")

        # If data type was JSON text from older frontend, read it normally
        if payload['data_type'] in ['json_payload', 'json_payload_v2', 'text']:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            os.remove(file_path)
            print(f"[API] 🔥 Text payload {record_id[:8]} burned.")
            return jsonify({"ciphertext": content, "data_type": payload['data_type']}), 200

        # For large binary files, stream the response to avoid RAM issues
        return Response(generate_and_burn(), mimetype='application/octet-stream')

    except Exception as e:
        print(f"[API Error] /api/retrieve: {str(e)}")
        return jsonify({"error": "Internal server error during retrieval."}), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"error": "File exceeds the 2 GB hardware limit."}), 413

# ==========================================
# 4. SERVER STARTUP
# ==========================================
if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 SECRETBRIDGE BACKEND V3 (HIGH-SPEED) IS ONLINE")
    print(f"🔒 API Key Auth: ENABLED (Constant-Time)")
    print("🤖 AI Security Shield: ACTIVE (Isolation Forest DDoS Guard)")
    print("💾 Storage Capacity: 2.0 GB per payload (Streaming Mode)")
    print("="*60 + "\n")
    
    # Threaded=True allows multiple concurrent high-speed uploads
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)
