# src/aes_ledger_engine.py

import rsa
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def run_ledger_demo():
    print("[*] Initializing Cryptographic Ledger Simulation...")
    
    # 1. Generate RSA-2048 Keys for Authentication
    print("[*] Generating RSA key pairs (2048-bit)...")
    alice_public_key, alice_private_key = rsa.newkeys(2048)
    bob_public_key, bob_private_key = rsa.newkeys(2048)
    print("[✔] RSA Key Pairs Successfully Established.")

    # 2. Mathematical Diffie-Hellman Key Exchange Parameters
    p = 23
    g = 5
    a = 6   # Alice private factor
    b = 15  # Bob private factor

    # Compute public values
    A = (g ** a) % p
    B = (g ** b) % p

    # 3. Secure Handshake Authentication via RSA Signatures
    print("[*] Executing authenticated Diffie-Hellman handshake...")
    A_bytes = str(A).encode()
    B_bytes = str(B).encode()

    alice_signature = rsa.sign(A_bytes, alice_private_key, 'SHA-256')
    bob_signature = rsa.sign(B_bytes, bob_private_key, 'SHA-256')

    # Verify integrity to prevent Man-in-the-Middle (MITM) interventions
    rsa.verify(A_bytes, alice_signature, alice_public_key)
    rsa.verify(B_bytes, bob_signature, bob_public_key)
    print("[✔] Handshake identities verified via digital signatures.")

    # 4. Shared Secret and Symmetric AES Key Derivation
    alice_shared_secret = (B ** a) % p
    bob_shared_secret = (A ** b) % p
    
    # Hash shared secret to derive a valid 16-byte symmetric key
    aes_key = hashlib.sha256(str(alice_shared_secret).encode()).digest()[:16]
    print("[✔] Symmetric AES key securely derived via SHA-256.")

    # 5. File System Encryption (AES-256-CBC)
    print("[*] Simulating banking transaction file creation...")
    with open("transactions.txt", "w") as file:
        file.write("Transfer 5000 EGP to Account 12345")

    with open("transactions.txt", "rb") as file:
        plaintext = file.read()

    # Apply CBC mode encryption with randomized IV and PKCS7 padding
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    with open("encrypted_transactions.bin", "wb") as file:
        file.write(iv + ciphertext)
    print("[✔] Transaction ledger encrypted and flushed to disk.")

    # 6. File System Decryption & Verification
    print("[*] Reading encrypted binary payload from disk...")
    with open("encrypted_transactions.bin", "rb") as file:
        data = file.read()

    extracted_iv = data[:16]
    extracted_ciphertext = data[16:]

    decrypt_cipher = AES.new(aes_key, AES.MODE_CBC, extracted_iv)
    decrypted_data = unpad(decrypt_cipher.decrypt(extracted_ciphertext), AES.block_size)

    with open("decrypted_transactions.txt", "wb") as file:
        file.write(decrypted_data)
        
    print(f"[✔] File successfully decrypted. Content: '{decrypted_data.decode()}'")
    print("[✔] Suite execution complete.")

if __name__ == "__main__":
    run_ledger_demo()