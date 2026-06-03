# src/network/client.py

import socket
import sys
import os

# Adjust path context to ensure local modules import seamlessly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.protocol.secure_protocol import (
    generate_dh_private_key, calculate_dh_public_value, 
    calculate_shared_secret, key_derivation_function
)
from src.ciphers.triple_des import triple_des_encrypt

def run_client(host='127.0.0.1', port=8585):
    """Connects to server, negotiates keys, and transmits encrypted string payloads."""
    print("[!] Spawning Secure Client Shell Subprocess...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((host, port))
        print(f"[+] Tunnel context attached directly to Gateway at {host}:{port}")
        
        # 1. Initialize Client-Side DH Parameter Primitives
        client_priv = generate_dh_private_key()
        client_pub = calculate_dh_public_value(client_priv)
        
        # 2. Transmit Local DH Parameter set
        client_socket.sendall(str(client_pub).encode('utf-8'))
        print(f"  [<-] Transmitted Local DH Public Parameter: {client_pub}")
        
        # 3. Capture Remote Handshake Parameters
        server_pub_raw = client_socket.recv(1024).decode('utf-8')
        server_pub = int(server_pub_raw)
        print(f"  [->] Received Peer DH Public Parameter: {server_pub}")
        
        # 4. Synthesize Symmetric Key Architecture via Shared Cryptographic Secret
        shared_secret = calculate_shared_secret(server_pub, client_priv)
        derived_3des_key = key_derivation_function(shared_secret)
        print(f"[!] Session Key Successfully Derived via Local KDF Pipeline.")
        
        # 5. Encrypt Cleartext Target via Custom Triple-DES Architecture
        target_plaintext = "Hello 3DES Encryption"
        print(f"\n[*] Compiling Secure Text Segment: '{target_plaintext}'")
        
        encrypted_stream = triple_des_encrypt(target_plaintext)
        
        # 6. Stream Ciphertext over the Open Network Socket Pipeline
        print("[*] Transmitting Bitstream to Remote Target Node...")
        client_socket.sendall(encrypted_stream.encode('utf-8'))
        print("[✔] Transaction Transmission Sequence Completed Successfully.")
        
    except Exception as e:
        print(f"[-] Structural network failure state detected: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    run_client()