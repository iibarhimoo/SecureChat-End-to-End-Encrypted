import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
import socket
import threading
import json
import base64
import hashlib
import os
import datetime

# --- CRYPTOGRAPHY LIBRARY ---
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ==========================================
# 1. LOGGING SYSTEM (Security Audit)
# ==========================================
def write_log(event_type, details):
    """Writes detailed cryptographic events to a log file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"\n[{timestamp}] --- {event_type} ---\n{details}\n{'-'*60}"
    
    with open("secure_chat_audit.log", "a", encoding="utf-8") as f:
        f.write(log_entry)

# ==========================================
# 2. CORE LOGIC (CRYPTO & UTILS)
# ==========================================

class CryptoHandler:
    @staticmethod
    def generate_id_keys():
        """Generates 2048-bit RSA Pair."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        return priv, pub

    @staticmethod
    def save_key(key, filename, is_private=False):
        """Saves a key to a PEM file."""
        with open(filename, "wb") as f:
            if is_private:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            else:
                f.write(key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

    @staticmethod
    def load_private_key(filename):
        with open(filename, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    @staticmethod
    def load_public_key(filename):
        with open(filename, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    @staticmethod
    def get_fingerprint(key_object):
        """Returns a short ID (First 6 chars of MD5 hash) to identify a key visually."""
        if hasattr(key_object, 'public_key'): 
            key_object = key_object.public_key()
            
        pem = key_object.public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.md5(pem).hexdigest()[:6].upper()

    @staticmethod
    def encrypt_message(sender_priv, recipient_pub, message_text):
        # 1. Generate Session Key (AES)
        session_key = os.urandom(32)
        
        # 2. Encrypt Message (AES-GCM)
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message_text.encode()) + encryptor.finalize()
        tag = encryptor.tag

        # 3. Encrypt Session Key (RSA-OAEP)
        encrypted_key = recipient_pub.encrypt(
            session_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # 4. Sign Original Message (RSA-PSS)
        signature = sender_priv.sign(
            message_text.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        # 5. Log Everything
        log_details = (
            f"Message: {message_text}\n"
            f"Generated AES Session Key (Hex): {session_key.hex()}\n"
            f"AES Nonce (Hex): {nonce.hex()}\n"
            f"AES Ciphertext (Hex): {ciphertext.hex()}\n"
            f"AES Tag (Hex): {tag.hex()}\n"
            f"Encrypted Session Key (RSA Block) (Hex): {encrypted_key.hex()[:64]}...[truncated]\n"
            f"Digital Signature (Hex): {signature.hex()[:64]}...[truncated]"
        )
        write_log("OUTGOING ENCRYPTION", log_details)

        # 6. Package
        return json.dumps({
            'enc_key': base64.b64encode(encrypted_key).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'signature': base64.b64encode(signature).decode()
        })

    @staticmethod
    def decrypt_message(my_priv_key, sender_pub_key, json_packet):
        packet = json.loads(json_packet)
        
        # 1. Decrypt Session Key
        try:
            enc_key = base64.b64decode(packet['enc_key'])
            session_key = my_priv_key.decrypt(
                enc_key,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
        except ValueError as e:
            write_log("DECRYPTION FAILURE", f"Failed to decrypt Session Key (RSA). Wrong Private Key?\nError: {e}")
            raise Exception("Wrong Key! This message was not encrypted for you.")

        # 2. Decrypt Content
        try:
            nonce = base64.b64decode(packet['nonce'])
            ciphertext = base64.b64decode(packet['ciphertext'])
            tag = base64.b64decode(packet['tag'])
            
            cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            decoded_msg = plaintext.decode()
        except Exception as e:
            write_log("DECRYPTION FAILURE", f"AES-GCM Integrity Check Failed.\nError: {e}")
            raise Exception("Integrity Check Failed (AES Tag Mismatch).")

        # 3. Verify Signature
        try:
            signature = base64.b64decode(packet['signature'])
            sender_pub_key.verify(
                signature,
                plaintext,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            verified_bool = True
        except Exception as e:
            verified_bool = False
            write_log("SIGNATURE FAILURE", f"Digital Signature verification failed.\nError: {e}")

        # 4. Log Success
        log_details = (
            f"Raw Packet Size: {len(json_packet)} bytes\n"
            f"Decrypted AES Session Key (Hex): {session_key.hex()}\n"
            f"Decrypted Message: {decoded_msg}\n"
            f"Signature Verification: {'VALID' if verified_bool else 'INVALID'}"
        )
        write_log("INCOMING DECRYPTION", log_details)

        return decoded_msg, verified_bool

# ==========================================
# 3. MODERN GUI APPLICATION
# ==========================================

class SecureChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureChat v2.0")
        self.root.geometry("1000x700")
        
        # --- State Variables ---
        self.my_priv_key = None
        self.my_pub_key = None
        self.target_pub_key = None
        self.socket = None
        
        # --- Style Configuration ---
        self._setup_styles()
        
        # --- Layout ---
        self._build_modern_gui()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam') # Clean, cross-platform look
        
        # Colors
        self.col_bg_sidebar = "#2c3e50"   # Dark Blue-Grey
        self.col_bg_chat = "#ecf0f1"      # Light Grey
        self.col_btn_primary = "#3498db"  # Blue
        self.col_btn_danger = "#e74c3c"   # Red
        self.col_text_light = "#ecf0f1"
        
        # Configure Widgets
        style.configure("Sidebar.TFrame", background=self.col_bg_sidebar)
        style.configure("SidebarLabel.TLabel", background=self.col_bg_sidebar, foreground=self.col_text_light, font=("Segoe UI", 10))
        style.configure("SidebarHeader.TLabel", background=self.col_bg_sidebar, foreground=self.col_text_light, font=("Segoe UI", 12, "bold"))
        
        style.configure("Chat.TFrame", background=self.col_bg_chat)
        
        # Custom Button Style
        style.configure("Action.TButton", font=("Segoe UI", 9, "bold"))

    def _build_modern_gui(self):
        # MAIN CONTAINER (Split Left/Right)
        main_paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashwidth=4, bg="#bdc3c7")
        main_paned.pack(fill=tk.BOTH, expand=True)

        # === LEFT SIDEBAR (Settings) ===
        sidebar = ttk.Frame(main_paned, style="Sidebar.TFrame", width=280)
        main_paned.add(sidebar)

        # 1. Identity Section
        ttk.Label(sidebar, text="👤 MY IDENTITY", style="SidebarHeader.TLabel").pack(pady=(20, 10), padx=15, anchor="w")
        
        btn_frame = ttk.Frame(sidebar, style="Sidebar.TFrame")
        btn_frame.pack(fill="x", padx=15)
        ttk.Button(btn_frame, text="✨ New Identity", command=self.generate_identity, style="Action.TButton").pack(side="left", fill="x", expand=True, padx=(0, 2))
        ttk.Button(btn_frame, text="📂 Load Key", command=self.load_my_identity, style="Action.TButton").pack(side="left", fill="x", expand=True, padx=(2, 0))
        
        self.lbl_my_id = ttk.Label(sidebar, text="Not Loaded", style="SidebarLabel.TLabel", font=("Consolas", 9))
        self.lbl_my_id.pack(pady=5, padx=15, anchor="w")

        ttk.Separator(sidebar, orient="horizontal").pack(fill="x", pady=15, padx=10)

        # 2. Connection Section
        ttk.Label(sidebar, text="🌐 NETWORK", style="SidebarHeader.TLabel").pack(pady=(0, 10), padx=15, anchor="w")
        
        # Grid layout for inputs inside sidebar
        conn_grid = ttk.Frame(sidebar, style="Sidebar.TFrame")
        conn_grid.pack(fill="x", padx=15)
        
        ttk.Label(conn_grid, text="IP:", style="SidebarLabel.TLabel").grid(row=0, column=0, sticky="w")
        self.ent_ip = ttk.Entry(conn_grid, width=15)
        self.ent_ip.insert(0, "127.0.0.1")
        self.ent_ip.grid(row=0, column=1, sticky="ew", padx=5)
        
        ttk.Label(conn_grid, text="Port:", style="SidebarLabel.TLabel").grid(row=1, column=0, sticky="w", pady=5)
        self.ent_port = ttk.Entry(conn_grid, width=6)
        self.ent_port.insert(0, "6000")
        self.ent_port.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        
        ttk.Button(sidebar, text="🔌 Connect", command=self.connect_server, style="Action.TButton").pack(fill="x", padx=15, pady=5)
        self.lbl_net_status = ttk.Label(sidebar, text="⚪ Offline", style="SidebarLabel.TLabel")
        self.lbl_net_status.pack(pady=2, padx=15, anchor="w")

        ttk.Separator(sidebar, orient="horizontal").pack(fill="x", pady=15, padx=10)

        # 3. Partner Section
        ttk.Label(sidebar, text="🔒 SECURE CHANNEL", style="SidebarHeader.TLabel").pack(pady=(0, 10), padx=15, anchor="w")
        
        ttk.Button(sidebar, text="👤 Load Partner's Key", command=self.load_target_key, style="Action.TButton").pack(fill="x", padx=15)
        self.lbl_target_id = ttk.Label(sidebar, text="Target: None", style="SidebarLabel.TLabel", font=("Consolas", 9))
        self.lbl_target_id.pack(pady=5, padx=15, anchor="w")

        # === RIGHT MAIN AREA (Chat) ===
        chat_frame = ttk.Frame(main_paned, style="Chat.TFrame")
        main_paned.add(chat_frame)

        # Chat History
        self.txt_chat = scrolledtext.ScrolledText(
            chat_frame, 
            wrap=tk.WORD, 
            font=("Segoe UI Emoji", 11), 
            bg="#ffffff", 
            fg="#2c3e50",
            state='disabled',
            padx=10, pady=10
        )
        self.txt_chat.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configure Tags for Bubbles
        self.txt_chat.tag_config("me", justify="right", foreground="#ffffff", background="#3498db", lmargin1=100, rmargin=10, spacing1=5, spacing3=5)
        self.txt_chat.tag_config("friend", justify="left", foreground="#2c3e50", background="#ecf0f1", lmargin1=10, rmargin=100, spacing1=5, spacing3=5)
        self.txt_chat.tag_config("system", justify="center", foreground="#95a5a6", font=("Segoe UI", 9, "italic"), spacing1=2, spacing3=2)
        self.txt_chat.tag_config("error", justify="center", foreground="#e74c3c", font=("Segoe UI", 9, "bold"))
        self.txt_chat.tag_config("valid_sig", foreground="#27ae60", font=("Segoe UI", 8, "bold"))
        self.txt_chat.tag_config("invalid_sig", foreground="#c0392b", font=("Segoe UI", 8, "bold"))

        # Input Area
        input_frame = ttk.Frame(chat_frame, style="Chat.TFrame")
        input_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.ent_msg = ttk.Entry(input_frame, font=("Segoe UI", 11))
        self.ent_msg.pack(side="left", fill="x", expand=True, padx=(0, 5), ipady=5)
        self.ent_msg.bind("<Return>", lambda e: self.send_message())
        
        send_btn = tk.Button(input_frame, text="➤ SEND", bg="#2ecc71", fg="white", font=("Segoe UI", 10, "bold"), 
                             relief="flat", padx=15, command=self.send_message)
        send_btn.pack(side="right")

    # --- ACTIONS ---

    def generate_identity(self):
        name = simpledialog.askstring("New Identity", "Enter your name (e.g. Alice):")
        if not name: return
        
        try:
            priv, pub = CryptoHandler.generate_id_keys()
            CryptoHandler.save_key(priv, f"{name}_private.pem", is_private=True)
            CryptoHandler.save_key(pub, f"{name}_public.pem", is_private=False)
            
            self.my_priv_key = priv
            self.my_pub_key = pub
            
            fid = CryptoHandler.get_fingerprint(pub)
            self.lbl_my_id.config(text=f"{name}\n🆔 {fid}", foreground="#2ecc71")
            self._log_gui("system", f"Generated keys for {name} [ID: {fid}]")
            messagebox.showinfo("Success", f"Identity Created!\nID: {fid}\nFiles saved locally.")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def load_my_identity(self):
        path = filedialog.askopenfilename(title="Select YOUR Private Key", filetypes=[("PEM Files", "*.pem")])
        if not path: return
        try:
            self.my_priv_key = CryptoHandler.load_private_key(path)
            self.my_pub_key = self.my_priv_key.public_key()
            
            fid = CryptoHandler.get_fingerprint(self.my_pub_key)
            name = os.path.basename(path).replace("_private.pem", "")
            
            self.lbl_my_id.config(text=f"{name}\n🆔 {fid}", foreground="#2ecc71")
            self._log_gui("system", f"Loaded Identity: {name} [ID: {fid}]")
        except Exception as e:
            messagebox.showerror("Load Error", f"Invalid Key File: {e}")

    def load_target_key(self):
        path = filedialog.askopenfilename(title="Select FRIEND'S Public Key", filetypes=[("PEM Files", "*.pem")])
        if not path: return
        try:
            self.target_pub_key = CryptoHandler.load_public_key(path)
            fid = CryptoHandler.get_fingerprint(self.target_pub_key)
            name = os.path.basename(path).replace("_public.pem", "")
            
            self.lbl_target_id.config(text=f"{name}\n🎯 {fid}", foreground="#3498db")
            self._log_gui("system", f"Target Locked: {name} [ID: {fid}]")
            
            if self.my_pub_key:
                my_fid = CryptoHandler.get_fingerprint(self.my_pub_key)
                if my_fid == fid:
                    messagebox.showwarning("Warning", "You loaded your OWN key as the target!")
                    
        except Exception as e:
            messagebox.showerror("Load Error", f"Invalid Key File: {e}")

    def connect_server(self):
        target_ip = self.ent_ip.get()
        port = int(self.ent_port.get())
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((target_ip, port))
            self.lbl_net_status.config(text=f"🟢 Online ({target_ip})", foreground="#2ecc71")
            
            threading.Thread(target=self.listen_for_messages, daemon=True).start()
            self._log_gui("system", f"Connected to Server at {target_ip}:{port}")
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

    def send_message(self):
        msg = self.ent_msg.get()
        if not msg: return
        if not self.my_priv_key:
            messagebox.showerror("Error", "Load your Identity first!")
            return
        if not self.target_pub_key:
            messagebox.showerror("Error", "Load a Friend's Public Key first!")
            return

        try:
            packet = CryptoHandler.encrypt_message(self.my_priv_key, self.target_pub_key, msg)
            self.socket.send(packet.encode())
            
            self._log_gui("me", f"{msg}  ") # Extra spaces for padding
            self.ent_msg.delete(0, tk.END)
            
        except Exception as e:
            self._log_gui("error", f"Could not send: {e}")

    def listen_for_messages(self):
        while True:
            try:
                data = self.socket.recv(8192)
                if not data: break
                self.root.after(0, self.process_packet, data)
            except:
                break

    def process_packet(self, data):
        try:
            if not self.my_priv_key or not self.target_pub_key:
                self._log_gui("system", "🔒 Encrypted message received (Load keys to decrypt)")
                return

            text, valid = CryptoHandler.decrypt_message(self.my_priv_key, self.target_pub_key, data.decode())
            
            if valid:
                self._log_gui("friend", f"  {text}")
                self._log_gui("valid_sig", "      ✓ Verified Identity")
            else:
                self._log_gui("friend", f"  {text}")
                self._log_gui("invalid_sig", "      ⚠ SIGNATURE INVALID")
                
        except Exception as e:
            self._log_gui("error", f"Decryption Failed: {e}")

    def _log_gui(self, tag, text):
        self.txt_chat.config(state='normal')
        self.txt_chat.insert(tk.END, text + "\n", (tag,))
        self.txt_chat.see(tk.END)
        self.txt_chat.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatClient(root)
    root.mainloop()