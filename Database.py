import sqlite3
import time
import threading
import uuid
import os
from cryptography.fernet import Fernet

# ==========================================
# 1. DATABASE & AUTO-DELETE SERVER
# ==========================================
class SecureDatabase:
    def __init__(self, db_name="ephemeral_vault.db"):
        self.db_name = db_name
        self._init_db()
        self.cleanup_interval = 30 # Check for expired items every 30 seconds
        self._start_cleanup_daemon()

    def _init_db(self):
        """Initialize the SQLite database with required tables."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            # We only store the ID, the ENCRYPTED data (ciphertext), the data type, and the expiry time.
            # The server NEVER sees the plaintext or the encryption key.
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vault (
                    id TEXT PRIMARY KEY,
                    ciphertext BLOB NOT NULL,
                    data_type TEXT NOT NULL,
                    expiry_time REAL NOT NULL
                )
            ''')
            conn.commit()

    def _start_cleanup_daemon(self):
        """Starts a background thread to automatically delete expired records."""
        daemon = threading.Thread(target=self._auto_delete_worker, daemon=True)
        daemon.start()
        print("[Server] Auto-delete daemon started.")

    def _auto_delete_worker(self):
        """Worker function that continuously removes expired items."""
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
                        print(f"\n[Server] Burned {expired_count} expired item(s) from the database.")
            except Exception as e:
                print(f"[Server] Cleanup error: {e}")
            
            time.sleep(self.cleanup_interval)

    def store_encrypted_data(self, ciphertext, data_type, lifespan_minutes=10):
        """Stores encrypted data with an expiration time."""
        record_id = str(uuid.uuid4())
        expiry_time = time.time() + (lifespan_minutes * 60)
        
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO vault (id, ciphertext, data_type, expiry_time) VALUES (?, ?, ?, ?)",
                (record_id, ciphertext, data_type, expiry_time)
            )
            conn.commit()
        return record_id

    def retrieve_encrypted_data(self, record_id):
        """Retrieves encrypted data if it hasn't expired."""
        current_time = time.time()
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ciphertext, data_type FROM vault WHERE id = ? AND expiry_time > ?",
                (record_id, current_time)
            )
            result = cursor.fetchone()
            
            if result:
                return {"ciphertext": result[0], "data_type": result[1]}
            return None

# ==========================================
# 2. E2EE CLIENT
# ==========================================
class SecureClient:
    def __init__(self):
        # In a real E2EE system, this key is generated on the user's device
        # and NEVER shared with the server.
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        print(f"[Client] Generated E2EE Key: {self.key.decode('utf-8')}")

    def encrypt_data(self, data: bytes):
        """Encrypts data before sending it to the database."""
        return self.cipher_suite.encrypt(data)

    def decrypt_data(self, ciphertext: bytes):
        """Decrypts data retrieved from the database."""
        return self.cipher_suite.decrypt(ciphertext)

    def read_file_as_bytes(self, filepath):
        """Helper to read a file (like an image) as bytes."""
        with open(filepath, 'rb') as f:
            return f.read()

    def save_bytes_to_file(self, data_bytes, output_filepath):
        """Helper to save decrypted bytes back to a file."""
        with open(output_filepath, 'wb') as f:
            f.write(data_bytes)

# ==========================================
# 3. DEMONSTRATION WORKFLOW
# ==========================================
if __name__ == "__main__":
    print("--- Starting Secure E2EE Ephemeral Vault ---\n")
    
    # Initialize Server (Database) and Client
    db = SecureDatabase()
    client = SecureClient()
    
    # ---------------------------------------------------------
    # Scenario A: Storing a Password (Text) for 10 minutes
    # ---------------------------------------------------------
    print("\n--- Scenario A: Storing a Password ---")
    my_password = "SuperSecretPassword123!"
    
    # Client encrypts the password
    encrypted_password = client.encrypt_data(my_password.encode('utf-8'))
    print(f"[Client] Encrypted Password. Ciphertext length: {len(encrypted_password)} bytes")
    
    # Client sends ENCRYPTED data to server. Set lifespan to 10 minutes.
    pass_id = db.store_encrypted_data(encrypted_password, "password", lifespan_minutes=10)
    print(f"[Server] Password stored safely. ID: {pass_id} (Expires in 10 mins)")

    # ---------------------------------------------------------
    # Scenario B: Storing a File (Image/Document)
    # ---------------------------------------------------------
    print("\n--- Scenario B: Storing a File ---")
    # Let's create a dummy image file for demonstration
    dummy_image_path = "dummy_image.jpg"
    with open(dummy_image_path, "wb") as f:
        f.write(os.urandom(1024)) # 1KB of random binary data to simulate an image

    # Client reads and encrypts the file
    file_bytes = client.read_file_as_bytes(dummy_image_path)
    encrypted_file = client.encrypt_data(file_bytes)
    
    # Client sends ENCRYPTED file to server. Let's set lifespan to 0.1 mins (6 seconds) 
    # so we can see the auto-delete daemon in action quickly!
    file_id = db.store_encrypted_data(encrypted_file, "image", lifespan_minutes=0.1)
    print(f"[Server] File stored safely. ID: {file_id} (Expires in 6 seconds to demo auto-delete)")

    # ---------------------------------------------------------
    # Retrieving and Decrypting Data
    # ---------------------------------------------------------
    print("\n--- Retrieving Data ---")
    # Retrieve Password
    retrieved_pass_data = db.retrieve_encrypted_data(pass_id)
    if retrieved_pass_data:
        decrypted_pass = client.decrypt_data(retrieved_pass_data["ciphertext"]).decode('utf-8')
        print(f"[Client] Successfully retrieved and decrypted password: {decrypted_pass}")
    
    # ---------------------------------------------------------
    # Waiting for Auto-Delete to trigger
    # ---------------------------------------------------------
    print("\n--- Waiting 10 seconds to observe Auto-Delete of the File ---")
    time.sleep(10) # Wait for the 6-second timer and the 5-second daemon interval
    
    # Try to retrieve the file after it should have been burned
    retrieved_file_data = db.retrieve_encrypted_data(file_id)
    if retrieved_file_data is None:
        print(f"[Client] Attempted to retrieve file {file_id}, but it was permanently deleted (burned)!")
    
    # Cleanup dummy file
    if os.path.exists(dummy_image_path):
        os.remove(dummy_image_path)

    print("\n--- Demonstration Complete ---")
    # The program will exit here, but in a real application, the server thread would run indefinitely.
