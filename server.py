# server.py
import socket
from des_encryption import decrypt_message  # Import DES decryption

# Server settings
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

# Create a TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_HOST, SERVER_PORT))
server_socket.listen()

print(f"Server started at {SERVER_HOST}:{SERVER_PORT}")

while True:
    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    while True:
        # Receive messages from the client
        encrypted_message = client_socket.recv(1024).decode()
        if not encrypted_message:
            break
        try:
            # Decrypt the received message
            message = decrypt_message(encrypted_message)
            print("Received:", message)
        except Exception as e:
            print("Failed to decrypt message:", e)
    
    client_socket.close()
    print(f"Connection closed from {client_address}")
