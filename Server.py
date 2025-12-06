import socket
import threading

# Configuration
DEFAULT_PORT = 6000
HOST = '0.0.0.0' # Listen on all network interfaces

clients = []

def broadcast(message, _client_socket):
    """Sends encrypted packet to everyone except the sender."""
    for client in clients:
        if client != _client_socket:
            try:
                client.send(message)
            except:
                if client in clients:
                    clients.remove(client)

def handle_client(client_socket):
    while True:
        try:
            message = client_socket.recv(8192) # 8KB buffer
            if not message:
                break
            broadcast(message, client_socket)
        except:
            if client_socket in clients:
                clients.remove(client_socket)
            client_socket.close()
            break

def start_server():
    print("--- 📨 SecureChat Post Office Server ---")
    port_input = input(f"Enter Port (Press Enter for {DEFAULT_PORT}): ")
    port = int(port_input) if port_input else DEFAULT_PORT

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HOST, port))
        server.listen()
        print(f"✅ Server listening on {HOST}:{port}")
        print(f"   (Share your IP address with the client)")
        
        while True:
            client_socket, addr = server.accept()
            print(f"🔗 New connection from: {addr}")
            clients.append(client_socket)
            thread = threading.Thread(target=handle_client, args=(client_socket,))
            thread.start()
    except OSError as e:
        print(f"❌ Error: Port {port} is busy. Close other server windows or try a different port.")

if __name__ == "__main__":
    start_server()