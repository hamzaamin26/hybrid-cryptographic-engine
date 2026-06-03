# src/protocol/secure_protocol.py

import hashlib
import secrets

# ==============================================================================
# DIFFIE-HELLMAN KEY EXCHANGE (FROM FIRST PRINCIPLES)
# ==============================================================================
# Shared Global Parameters (Using standard safe primes for demonstration)
DH_PRIME = 23    # Publicly known prime (p)
DH_BASE = 5      # Publicly known primitive root generator (g)

def generate_dh_private_key():
    """Generates a random secure private exponent chosen from the group field."""
    return secrets.randbelow(DH_PRIME - 2) + 2

def calculate_dh_public_value(private_key):
    """Computes the public value to exchange over the network: (g^priv) % p."""
    return pow(DH_BASE, private_key, DH_PRIME)

def calculate_shared_secret(peer_public, your_private):
    """Computes the raw shared secret value: (peer_pub^your_priv) % p."""
    return pow(peer_public, your_private, DH_PRIME)

def key_derivation_function(shared_secret_int):
    """
    KDF Pipeline: Converts the algebraic integer secret into a high-entropy 
    48-character binary bitstring required by our custom 3DES engine.
    """
    secret_bytes = str(shared_secret_int).encode('utf-8')
    # Use SHA-256 to distribute entropy evenly
    sha256_hash = hashlib.sha256(secret_bytes).hexdigest()
    
    # Convert hex hash into a continuous bit string
    full_bitstring = "".join(format(int(char, 16), '04b') for char in sha256_hash)
    
    # Return a deterministic 48-bit string slice to match the round-key size
    return full_bitstring[:48]

# ==============================================================================
# RSA ASYMMETRIC DIGITAL SIGNATURE ENGINE 
# ==============================================================================
def extended_gcd(a, b):
    """Extended Euclidean Algorithm to find modular multiplicative inverses."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e, phi):
    """Calculates the private decryption exponent d given e and Phi(n)."""
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist.")
    return x % phi

def generate_rsa_keys():
    """Generates a simple mock RSA keypair for identity authentication."""
    # Hardcoded small primes for academic principle demonstration
    p, q = 61, 53
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 17  # Standard public exponent choice
    d = mod_inverse(e, phi)
    
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def rsa_sign_payload(private_key, message_str):
    """
    Signs a message payload using the sender's private key.
    Calculates: Signature = (Hash(M)^d) % n
    """
    d, n = private_key
    # Hash the payload to generate a message digest integer
    msg_hash = int(hashlib.sha256(message_str.encode('utf-8')).hexdigest(), 16) % n
    
    # Compute signature via modular exponentiation
    signature = pow(msg_hash, d, n)
    return signature

def rsa_verify_signature(public_key, message_str, signature_int):
    """
    Verifies payload authenticity using the sender's public key.
    Checks if: (Signature^e) % n == Hash(M) % n
    """
    e, n = public_key
    msg_hash = int(hashlib.sha256(message_str.encode('utf-8')).hexdigest(), 16) % n
    
    # Decrypt the signature value using public component
    decrypted_hash = pow(signature_int, e, n)
    
    # Identity is verified if hashes align perfectly
    return decrypted_hash == msg_hash

# ==============================================================================
# LOCAL SANITY CHECK RUNNER
# ==============================================================================
if __name__ == "__main__":
    print("[!] Simulating Cryptographic Handshake Protocol Setup...\n")
    
    # 1. Simulate Diffie-Hellman Key Agreement
    alice_priv = generate_dh_private_key()
    alice_pub = calculate_dh_public_value(alice_priv)
    
    bob_priv = generate_dh_private_key()
    bob_pub = calculate_dh_public_value(bob_priv)
    
    # Exchange public keys and calculate shared secrets independently
    alice_secret = calculate_shared_secret(bob_pub, alice_priv)
    bob_secret = calculate_shared_secret(alice_pub, bob_priv)
    
    print(f"[*] Diffie-Hellman Results:")
    print(f"  -> Alice Shared Secret Base: {alice_secret}")
    print(f"  -> Bob Shared Secret Base  : {bob_secret}")
    assert alice_secret == bob_secret, "DH Key Agreement Failed!"
    
    # Derive operational 3DES symmetric key via KDF
    derived_key = key_derivation_function(alice_secret)
    print(f"  -> Derived 3DES Ready Bit-Key via KDF: {derived_key}\n")
    
    # 2. Simulate RSA Digital Signature Identity Validation
    pub_key, priv_key = generate_rsa_keys()
    payload_data = f"DH_PUB_EXCHANGE:{alice_pub}"
    
    print(f"[*] RSA Digital Signature Results:")
    print(f"  -> Original Payload: '{payload_data}'")
    
    sig = rsa_sign_payload(priv_key, payload_data)
    print(f"  -> Generated RSA Signature Integer: {sig}")
    
    is_valid = rsa_verify_signature(pub_key, payload_data, sig)
    print(f"  -> Signature Verification Success State: {is_valid}")