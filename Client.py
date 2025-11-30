import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
import socket
import threading
import json
import base64
import hashlib
import os

# --- CRYPTOGRAPHY LIBRARY ---
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ==========================================
# 1. CORE LOGIC (CRYPTO & UTILS)
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
        if hasattr(key_object, 'public_key'): # If it's private, extract public part
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

        # 3. Encrypt Session Key (RSA-OAEP) -> Locked for Recipient
        encrypted_key = recipient_pub.encrypt(
            session_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # 4. Sign Original Message (RSA-PSS) -> Prove Sender
        signature = sender_priv.sign(
            message_text.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        # 5. Package
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
        except ValueError:
            raise Exception("Wrong Key! This message was not encrypted for you.")

        # 2. Decrypt Content
        try:
            nonce = base64.b64decode(packet['nonce'])
            ciphertext = base64.b64decode(packet['ciphertext'])
            tag = base64.b64decode(packet['tag'])
            
            cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception:
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
            return plaintext.decode(), True # True = Verified
        except Exception:
            return plaintext.decode(), False # False = Signature Invalid

# ==========================================
# 2. GUI APPLICATION
# ==========================================

class SecureChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureChat v3.0 (Robust)")
        self.root.geometry("900x650")

        self.my_priv_key = None
        self.my_pub_key = None
        self.target_pub_key = None
        self.socket = None

        self._build_gui()

    def _build_gui(self):
        # --- SECTION 1: IDENTITY ---
        f_id = ttk.LabelFrame(self.root, text="1. My Identity", padding=10)
        f_id.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(f_id, text="🆕 Generate New Identity", command=self.generate_identity).pack(side="left", padx=5)
        ttk.Button(f_id, text="📂 Load Existing Private Key", command=self.load_my_identity).pack(side="left", padx=5)
        self.lbl_my_id = ttk.Label(f_id, text="Status: No Identity Loaded", foreground="red", font=("Arial", 10, "bold"))
        self.lbl_my_id.pack(side="left", padx=20)

        # --- SECTION 2: CONNECTION ---
        f_net = ttk.LabelFrame(self.root, text="2. Network", padding=10)
        f_net.pack(fill="x", padx=10, pady=5)

        ttk.Label(f_net, text="Port:").pack(side="left")
        self.ent_port = ttk.Entry(f_net, width=6)
        self.ent_port.insert(0, "6000")
        self.ent_port.pack(side="left", padx=5)
        
        ttk.Button(f_net, text="🔌 Connect to Server", command=self.connect_server).pack(side="left", padx=5)
        self.lbl_net_status = ttk.Label(f_net, text="Offline", foreground="red")
        self.lbl_net_status.pack(side="left", padx=20)

        # --- SECTION 3: CHAT AREA ---
        self.txt_chat = scrolledtext.ScrolledText(self.root, height=15, state='disabled', font=("Consolas", 10))
        self.txt_chat.pack(fill="both", expand=True, padx=10, pady=5)

        # --- SECTION 4: TARGET & SEND ---
        f_send = ttk.LabelFrame(self.root, text="3. Secure Messaging", padding=10)
        f_send.pack(fill="x", padx=10, pady=10)

        ttk.Button(f_send, text="👤 Load Friend's Public Key", command=self.load_target_key).pack(side="left")
        self.lbl_target_id = ttk.Label(f_send, text="Target: None", foreground="gray")
        self.lbl_target_id.pack(side="left", padx=10)

        self.ent_msg = ttk.Entry(f_send, font=("Arial", 11))
        self.ent_msg.pack(side="left", fill="x", expand=True, padx=10)
        self.ent_msg.bind("<Return>", lambda e: self.send_message())
        
        ttk.Button(f_send, text="📨 SEND", command=self.send_message).pack(side="right")

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
            self.lbl_my_id.config(text=f"Identity: {name} [ID: {fid}]", foreground="green")
            self._log(f"[SYSTEM] generated new keys for {name}. ID: {fid}")
            messagebox.showinfo("Success", f"Identity Created!\nID: {fid}\nFiles saved: {name}_private.pem / {name}_public.pem")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def load_my_identity(self):
        path = filedialog.askopenfilename(title="Select YOUR Private Key", filetypes=[("Private Key", "*private.pem")])
        if not path: return
        try:
            self.my_priv_key = CryptoHandler.load_private_key(path)
            self.my_pub_key = self.my_priv_key.public_key()
            
            fid = CryptoHandler.get_fingerprint(self.my_pub_key)
            name = os.path.basename(path).replace("_private.pem", "")
            
            self.lbl_my_id.config(text=f"Identity: {name} [ID: {fid}]", foreground="green")
            self._log(f"[SYSTEM] Loaded Identity: {name} [ID: {fid}]")
        except Exception as e:
            messagebox.showerror("Load Error", f"Invalid Key File: {e}")

    def load_target_key(self):
        path = filedialog.askopenfilename(title="Select FRIEND'S Public Key", filetypes=[("Public Key", "*public.pem")])
        if not path: return
        try:
            self.target_pub_key = CryptoHandler.load_public_key(path)
            fid = CryptoHandler.get_fingerprint(self.target_pub_key)
            name = os.path.basename(path).replace("_public.pem", "")
            
            self.lbl_target_id.config(text=f"Target: {name} [ID: {fid}]", foreground="blue", font=("Arial", 10, "bold"))
            self._log(f"[SYSTEM] Target Locked: {name} [ID: {fid}]")
            
            # Safety Check
            if self.my_pub_key:
                my_fid = CryptoHandler.get_fingerprint(self.my_pub_key)
                if my_fid == fid:
                    messagebox.showwarning("Warning", "You loaded your OWN key as the target!\nYou cannot send messages to yourself.")
                    
        except Exception as e:
            messagebox.showerror("Load Error", f"Invalid Key File: {e}")

    def connect_server(self):
        port = int(self.ent_port.get())
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect(('127.0.0.1', port))
            self.lbl_net_status.config(text="Online", foreground="green")
            
            threading.Thread(target=self.listen_for_messages, daemon=True).start()
            self._log(f"[SYSTEM] Connected to Server on port {port}")
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
            # Encrypt
            packet = CryptoHandler.encrypt_message(self.my_priv_key, self.target_pub_key, msg)
            
            # Send
            self.socket.send(packet.encode())
            
            # Log
            self._log(f"[ME]: {msg}", "black")
            self.ent_msg.delete(0, tk.END)
            
        except Exception as e:
            self._log(f"[ERROR]: Could not send ({e})", "red")

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
            # Attempt Decrypt
            if not self.my_priv_key or not self.target_pub_key:
                self._log("[INCOMING] Encrypted message received (Keys not loaded yet).", "gray")
                return

            text, valid = CryptoHandler.decrypt_message(self.my_priv_key, self.target_pub_key, data.decode())
            
            if valid:
                self._log(f"[FRIEND]: {text}", "blue")
            else:
                self._log(f"[WARNING]: {text} (Signature Invalid!)", "orange")
                
        except Exception as e:
            # This catches "Wrong Key" errors
            self._log(f"[DROP]: Decryption Failed - {e}", "red")

    def _log(self, text, color="black"):
        self.txt_chat.config(state='normal')
        self.txt_chat.insert(tk.END, text + "\n", (color,))
        self.txt_chat.tag_config(color, foreground=color)
        self.txt_chat.see(tk.END)
        self.txt_chat.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatClient(root)
    root.mainloop()