import os
import time
import sqlite3
import threading
import uuid
import hmac
import numpy as np
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from werkzeug.utils import secure_filename
from sklearn.ensemble import IsolationForest

# ==========================================
# CONFIGURATION & CONSTANTS
# ==========================================
app = Flask(__name__)
CORS(app)

# 2 GB Upload limit
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024 

# Storage Directories
VAULT_DIR = "./vault_storage"
TEMP_DIR = "./vault_temp"
os.makedirs(VAULT_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

API_KEY = "super_secret_bridge_api_key_2024"
DB_NAME = "secret_bridge_prod.db"

# ==========================================
# 1. MACHINE LEARNING: AI SECURITY SHIELD
# ==========================================
class AISecurityShield:
    def __init__(self):
        self.model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
        self.ip_history = {}
        self._pre_train_model()
        print("[AI Shield] Anomaly Detection Model Initialized.")

    def _pre_train_model(self):
        # Features: [content_length_mb, seconds_since_last_req, total_reqs_today]
        # Chunking ke liye requests zyada hongi, isliye baseline update kiya gaya hai
        normal_traffic = np.array([
            [5.0, 300, 1], [15.0, 1500, 2], [5.0, 1, 50],  # Parallel chunks baseline
            [1.0, 60, 5], [200.0, 86400, 1], [10.0, 600, 3]
        ])
        self.model.fit(normal_traffic)

    def analyze_request(self, ip_address, content_length):
        current_time = time.time()
        length_mb = (content_length or 0) / (1024 * 1024)

        if ip_address not in self.ip_history:
            self.ip_history[ip_address] = {'last_req': current_time, 'count': 1}
            return False 

        history = self.ip_history[ip_address]
        time_diff = current_time - history['last_req']
        history['last_req'] = current_time
        history['count'] += 1

        features = np.array([[length_mb, time_diff, history['count']]])
        prediction = self.model.predict(features)[0]
        
        if prediction == -1 and time_diff > 2: # Ignore rapid chunk bursts from anomaly
            print(f"[AI Shield] 🚨 Anomaly detected from IP: {ip_address}")
            return True
        return False

ai_shield = AISecurityShield()

# ==========================================
# 2. STRONG SQL DATABASE MANAGER
# ==========================================
class SecureVaultManager:
    def __init__(self, db_file=DB_NAME):
        self.db_file = db_file
        self._init_db()
        self._start_cleanup_daemon()

    def _init_db(self):
        """Production level normalized schema with WAL mode"""
        with sqlite3.connect(self.db_file) as conn:
            conn.execute("PRAGMA journal_mode=WAL;") # Fast concurrency
            conn.execute("PRAGMA synchronous=NORMAL;")
            cursor = conn.cursor()
            
            # Vaults Table (Session details)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vaults (
                    vault_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )
            ''')
            # Text Messages Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vault_texts (
                    vault_id TEXT PRIMARY KEY,
                    ciphertext TEXT NOT NULL,
                    FOREIGN KEY(vault_id) REFERENCES vaults(vault_id) ON DELETE CASCADE
                )
            ''')
            # Files Table (Chunk tracking & metadata)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vault_files (
                    file_id TEXT PRIMARY KEY,
                    vault_id TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    mime_type TEXT,
                    file_size INTEGER,
                    file_path TEXT NOT NULL,
                    total_chunks INTEGER NOT NULL,
                    uploaded_chunks INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'pending',
                    FOREIGN KEY(vault_id) REFERENCES vaults(vault_id) ON DELETE CASCADE
                )
            ''')
            conn.commit()
        print(f"[Database] SQLite WAL DB Initialized.")

    def _start_cleanup_daemon(self):
        daemon = threading.Thread(target=self._auto_delete_worker, daemon=True)
        daemon.start()

    def _auto_delete_worker(self):
        """Automatically burns expired files from SSD and DB"""
        while True:
            try:
                current_time = time.time()
                with sqlite3.connect(self.db_file) as conn:
                    cursor = conn.cursor()
                    
                    # Find expired vaults
                    cursor.execute("SELECT vault_id FROM vaults WHERE expires_at <= ?", (current_time,))
                    expired_vaults = cursor.fetchall()
                    
                    for (v_id,) in expired_vaults:
                        # Get associated files to delete from SSD
                        cursor.execute("SELECT file_path FROM vault_files WHERE vault_id = ?", (v_id,))
                        for (fpath,) in cursor.fetchall():
                            if os.path.exists(fpath):
                                os.remove(fpath)
                                
                        # Delete temp chunks if any left
                        for f in os.listdir(TEMP_DIR):
                            if f.startswith(v_id):
                                os.remove(os.path.join(TEMP_DIR, f))
                                
                        # Cascade delete will handle DB records
                        cursor.execute("DELETE FROM vaults WHERE vault_id = ?", (v_id,))
                        
                    if expired_vaults:
                        conn.commit()
                        print(f"[Daemon] 🔥 Auto-Burned {len(expired_vaults)} expired vault(s).")
            except Exception as e:
                print(f"[Daemon Error] {e}")
            time.sleep(60)

vault_manager = SecureVaultManager()

# ==========================================
# 3. SECURE CHUNK API ENDPOINTS
# ==========================================
def require_api_key(func):
    def wrapper(*args, **kwargs):
        provided_key = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(provided_key, API_KEY):
            return jsonify({"error": "Unauthorized"}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@app.route('/api/vault/init', methods=['POST'])
@require_api_key
def init_vault():
    """Step 1: Vault aur Secure Text initialize karna"""
    data = request.json
    vault_id = data.get('id')
    text_cipher = data.get('text_ciphertext')
    
    expires_at = time.time() + (10 * 60) # 10 Mins expiry
    
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO vaults (vault_id, created_at, expires_at) VALUES (?, ?, ?)", 
                           (vault_id, time.time(), expires_at))
            if text_cipher:
                cursor.execute("INSERT INTO vault_texts (vault_id, ciphertext) VALUES (?, ?)", 
                               (vault_id, text_cipher))
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "Vault ID collision."}), 409
            
    return jsonify({"message": "Vault initialized"}), 200

@app.route('/api/vault/chunk', methods=['POST'])
@require_api_key
def upload_chunk():
    """Step 2: Parallel chunks receive karna"""
    vault_id = request.form.get('vault_id')
    file_id = request.form.get('file_id')
    chunk_index = int(request.form.get('chunk_index'))
    total_chunks = int(request.form.get('total_chunks'))
    
    file_name = secure_filename(request.form.get('file_name', 'enc_file'))
    mime_type = request.form.get('mime_type', 'application/octet-stream')
    file_size = int(request.form.get('file_size', 0))
    chunk_data = request.files['chunk']

    # Agar pehla chunk hai toh DB me file register karein
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        final_path = os.path.join(VAULT_DIR, f"{file_id}.enc")
        cursor.execute("""
            INSERT OR IGNORE INTO vault_files 
            (file_id, vault_id, file_name, mime_type, file_size, file_path, total_chunks) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (file_id, vault_id, file_name, mime_type, file_size, final_path, total_chunks))
        conn.commit()
    
    # Save chunk temporary
    chunk_path = os.path.join(TEMP_DIR, f"{vault_id}_{file_id}.part{chunk_index}")
    chunk_data.save(chunk_path)
    
    # Update count and stitch if complete
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE vault_files SET uploaded_chunks = uploaded_chunks + 1 WHERE file_id = ?", (file_id,))
        cursor.execute("SELECT uploaded_chunks, total_chunks, file_path FROM vault_files WHERE file_id = ?", (file_id,))
        uploaded, total, fpath = cursor.fetchone()
        
        if uploaded == total:
            # Pura file aa gaya, chunks ko merge karo
            with open(fpath, 'wb') as outfile:
                for i in range(total):
                    cpath = os.path.join(TEMP_DIR, f"{vault_id}_{file_id}.part{i}")
                    with open(cpath, 'rb') as infile:
                        outfile.write(infile.read())
                    os.remove(cpath)
            
            cursor.execute("UPDATE vault_files SET status = 'ready' WHERE file_id = ?", (file_id,))
        conn.commit()
            
    return jsonify({"status": "Chunk received"}), 200

@app.route('/api/vault/metadata/<vault_id>', methods=['GET'])
@require_api_key
def get_metadata(vault_id):
    """Step 3: Download ke time files ki list aur text fetch karna"""
    current_time = time.time()
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT expires_at FROM vaults WHERE vault_id = ? AND expires_at > ?", (vault_id, current_time))
        if not cursor.fetchone():
            return jsonify({"error": "Vault not found or expired"}), 404
            
        cursor.execute("SELECT ciphertext FROM vault_texts WHERE vault_id = ?", (vault_id,))
        text_row = cursor.fetchone()
        text_cipher = text_row[0] if text_row else None
        
        cursor.execute("SELECT file_id, file_name, mime_type, file_size FROM vault_files WHERE vault_id = ? AND status = 'ready'", (vault_id,))
        files = [{"file_id": r[0], "file_name": r[1], "mime_type": r[2], "file_size": r[3]} for r in cursor.fetchall()]
        
    return jsonify({"text_ciphertext": text_cipher, "files": files}), 200

@app.route('/api/vault/download/<file_id>', methods=['GET'])
@require_api_key
def download_file(file_id):
    """Step 4: Real file ko memory stream karke client ko bhejna aur SSD se burn karna"""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT file_path FROM vault_files WHERE file_id = ?", (file_id,))
        row = cursor.fetchone()
        
    if not row or not os.path.exists(row[0]):
        return jsonify({"error": "File burned or not found"}), 404
        
    file_path = row[0]

    def generate_and_burn():
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(1024 * 1024): # 1MB stream chunks
                    yield chunk
        finally:
            # File download hote hi permanent burn
            if os.path.exists(file_path):
                os.remove(file_path)
                with sqlite3.connect(DB_NAME) as conn:
                    conn.execute("DELETE FROM vault_files WHERE file_id = ?", (file_id,))
                print(f"[API] 🔥 File {file_path} burned after download.")

    return Response(generate_and_burn(), mimetype='application/octet-stream')

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 SECRETBRIDGE BACKEND V4 (PRODUCTION CHUNKING) IS ONLINE")
    print("🗄️ Database: SQLite (WAL Mode for high concurrency)")
    print("⚡ Upload Strategy: Parallel Chunking")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)
