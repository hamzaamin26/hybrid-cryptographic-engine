# src/network/server.py

import socket
import sys
import os

# Adjust path context to ensure local modules import seamlessly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.protocol.secure_protocol import (
    generate_dh_private_key, calculate_dh_public_value, 
    calculate_shared_secret, key_derivation_function
)
from src.ciphers.triple_des import triple_des_decrypt

def run_server(host='127.0.0.1', port=8585):
    """Initializes a localized TCP listener to process encrypted handshakes."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow local port reuse to avoid 'Address already in use' errors
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"[+] Secure Banking Vault listening on TCP://{host}:{port}...")
    
    try:
        conn, addr = server_socket.accept()
        print(f"[+] Dynamic connection established from secure node: {addr}")
        
        # 1. Initialize Server-Side DH Parameter Primitives
        server_priv = generate_dh_private_key()
        server_pub = calculate_dh_public_value(server_priv)
        
        # 2. Receive Client's Public Key Parameter Array
        client_pub_raw = conn.recv(1024).decode('utf-8')
        client_pub = int(client_pub_raw)
        print(f"  [->] Received Peer DH Public Parameter: {client_pub}")
        
        # 3. Transmit Server's Public Key back to Client
        conn.sendall(str(server_pub).encode('utf-8'))
        print(f"  [<-] Transmitted Local DH Public Parameter: {server_pub}")
        
        # 4. Synthesize Symmetric Key Architecture via Shared Cryptographic Secret
        shared_secret = calculate_shared_secret(client_pub, server_priv)
        derived_3des_key = key_derivation_function(shared_secret)
        print(f"[!] Session Key Successfully Derived via Local KDF Pipeline.")
        
        # 5. Intercept and Decrypt Incoming Encrypted Traffic Streams
        encrypted_bitstream = conn.recv(4096).decode('utf-8')
        print(f"\n[?] Intercepted Binary Inbound Payload: \n{encrypted_bitstream}")
        
        print("\n[*] Processing Inbound Stream Decryption via 3DES Engine...")
        decrypted_message = triple_des_decrypt(encrypted_bitstream)
        
        print(f"\n[✔] Structural Decryption Cleartext Outcome: '{decrypted_message}'")
        
        conn.close()
    except Exception as e:
        print(f"[-] Operational runtime breakdown triggered: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    run_server()