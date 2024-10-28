from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import socket
import os

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(message, public_key):
    # Encrypt the message using the recipient's public key
    cipher = Cipher(algorithms.AES(os.urandom(32)), modes.CBC(os.urandom(16)), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return public_key.encrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def decrypt_message(ciphertext, private_key):
    # Decrypt the message using the private key
    ciphertext = private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    cipher = Cipher(algorithms.AES(os.urandom(32)), modes.CBC(os.urandom(16)), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

def send_message(sock, message, public_key):
    # Send the encrypted message
    encrypted_message = encrypt_message(message, public_key)
    sock.sendall(encrypted_message)

def receive_message(sock, private_key):
    # Receive and decrypt the message
    data = sock.recv(1024)
    if data:
        decrypted_message = decrypt_message(data, private_key)
        return decrypted_message
    else:
        return None

def main():
    host = '192.168.1.10'  # IP address of the server (replace with the server's IP address)
    port = 5000  # Port for connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((host, port))

            print("Connection established!")

            # Generate RSA keys
            private_key, public_key = generate_rsa_keys()

            # Send public key to the server
            sock.sendall(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            # Receive server's public key
            server_public_key_data = sock.recv(1024)
            server_public_key = serialization.load_pem_public_key(
                server_public_key_data,
                backend=default_backend()
            )

            while True:
                message = input("Enter your message: ")
                if message == 'exit':
                    break
                send_message(sock, message, server_public_key)

                received_message = receive_message(sock, private_key)
                if received_message:
                    print("Received message:", received_message)

        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()