# src/ciphers/triple_des.py

# ==============================================================================
# DES TABLES PROVIDED BY USER
# ==============================================================================
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

S_BOXES = [
    [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],

    [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],

    [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],

    [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],

    [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],

    [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],

    [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]],

    [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]]
]

# 16 round keys (48 bits each)
first_16_round_keys = ['000010110000001001100111100110110100100110100101', '011010011010011001011001001001010110101000100110', '010001011101010010001010101101000010100011010010', '011100101000100111010010101001011000001001010111', '001111001110100000000011000101111010011011000010', '001000110010010100011110001111001000010101000101', '011011000000010010010101000010101110010011000110', '010101111000100000111000011011001110010110000001', '110000001100100111101001001001101011100000111001', '100100011110001100000111011000110001110101110010', '001000010001111110000011000011011000100100111010', '011100010011000011100101010001010101110001010100', '100100011100010011010000010010011000000011111100', '010101000100001110110110100000011101110010001101', '101101101001000100000101000010100001011010110101', '110010100011110100000011101110000111000000110010']
second_16_round_keys = ['111101001111110110011000011001001011011001011010', '100101100101100110100110110110101001010111011001', '101110100010101101110101010010111101011100101101', '100011010111011000101101010110100111110110101000', '110000110001011111111100111010000101100100111101', '110111001101101011100001110000110111101010111010', '100100111111101101101010111101010001101100111001', '101010000111011111000111100100110001101001111110', '001111110011011000010110110110010100011111000110', '011011100001110011111000100111001110001010001101', '110111101110000001111100111100100111011011000101', '100011101100111100011010101110101010001110101011', '011011100011101100101111101101100111111100000011', '101010111011110001001001011111100010001101110010', '010010010110111011111010111101011110100101001010', '001101011100001011111100010001111000111111001101']
third_16_round_keys = ['000001000100001101110110100100111001010110001101', '011001101110011101010000001011010011011000001110', '010011101101010100000011001111000111000011100010', '011010111000000101011011001001001100100001100111', '001011011100000010001011100001101010110011010010', '001100110000100110011010101011011000011101010001', '001111000010100010010001000110111100011001000010', '000101110010110000011100010111001100010100000100', '000000000110110111001101000101001001100010111100', '010100010110010100100101010000010011110011110001', '110000011000110110100001001010111010100000111001', '110100011010001010100111001000110101110100010110', '101100011001011010000010000011010000000110110110', '011100000001001011100110110001010100100011000101', '101100001101000001010100010000101000001011011101', '110001000111110001010010111100001010010000011010']

# ==============================================================================
# BIT MANIPULATION HELPERS
# ==============================================================================
def text_to_bit_string(text):
    """Converts a standard text string to a string of binary bits (8-bits/char)."""
    return "".join(format(ord(char), '08b') for char in text)

def bit_string_to_text(bit_str):
    """Converts a string of binary bits back into an ASCII text string."""
    chars = []
    for i in range(0, len(bit_str), 8):
        byte = bit_str[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return "".join(chars)

def pkcs7_pad(text):
    """Pads text to 64-bit (8 byte) block boundaries using PKCS#7 format."""
    pad_len = 8 - (len(text) % 8)
    return text + (chr(pad_len) * pad_len)

def pkcs7_unpad(text):
    """Removes PKCS#7 padding safely from decrypted text."""
    pad_len = ord(text[-1])
    if pad_len < 1 or pad_len > 8:
        return text  # No valid padding detected
    return text[:-pad_len]

def permute(bit_str, table):
    """Rearranges elements inside a bit string using 1-indexed mapping tables."""
    return "".join(bit_str[index - 1] for index in table)

def xor_strings(str1, str2):
    """Performs bitwise XOR operations across two binary character strings."""
    return "".join('1' if b1 != b2 else '0' for b1, b2 in zip(str1, str2))

# ==============================================================================
# FEISTEL FUNCTION F() & CORE DES ENGINE
# ==============================================================================
def feistel_f(right_half, round_key, s_box_index=None, verbose=False):
    """Executes the standard DES Feistel cipher function components."""
    # 1. Expansion (32 bits -> 48 bits)
    expanded = permute(right_half, E)
    
    # 2. Key Mixing (XOR with 48-bit Round Key)
    mixed = xor_strings(expanded, round_key)
    
    # 3. S-Box Substitutions (48 bits -> 32 bits)
    sbox_output = ""
    for i in range(8):
        chunk = mixed[i*6 : (i+1)*6]
        # Row: first and last bit
        row = int(chunk + chunk[5], 2)
        # Column: middle 4 bits
        col = int(chunk[1:5], 2)
        
        val = S_BOXES[i][row][col]
        sbox_output += format(val, '04b')
        
    # 4. Straight Permutation (32 bits -> 32 bits)
    final_p = permute(sbox_output, P)
    
    if verbose and s_box_index == 0:
        print(f"\n      [ROUND 1 DETAIL RUNLOG]")
        print(f"      * Right Half Input : {right_half}")
        print(f"      * E-Expansion Output: {expanded}")
        print(f"      * XOR Round Key Mix : {mixed}")
        print(f"      * S-Box Substitutes : {sbox_output}")
        print(f"      * P-Permutation Out : {final_p}")
        
    return final_p

def des_block_operation(block_64, round_keys, mode="ENCRYPT", block_id=0):
    """Processes a single 64-bit block using 16 Feistel transformation rounds."""
    # If in Decryption Mode, reverse the 16-round key processing hierarchy
    keys_to_use = round_keys[::-1] if mode == "DECRYPT" else round_keys
    
    # Initial Permutation (IP)
    current_state = permute(block_64, IP)
    L = current_state[:32]
    R = current_state[32:]
    
    for round_idx in range(16):
        # Trigger detailed step printouts only for the first round of Block 0
        is_verbose = (block_id == 0 and round_idx == 0)
        
        new_L = R
        f_output = feistel_f(R, keys_to_use[round_idx], round_idx, verbose=is_verbose)
        new_R = xor_strings(L, f_output)
        
        L, R = new_L, new_R
        
    # Final 16th Round Half-Swap Structure
    pre_output = R + L
    
    # Final Permutation (FP)
    return permute(pre_output, FP)

# ==============================================================================
# TRIPLE-DES EDE WRAPPER
# ==============================================================================
def triple_des_encrypt(plaintext_str):
    """Executes full Triple-DES EDE encryption across all data text blocks."""
    padded_text = pkcs7_pad(plaintext_str)
    bit_string = text_to_bit_string(padded_text)
    
    ciphertext_bits = ""
    print(f"[!] Beginning 3DES Block Isolation Pipeline...")
    
    # Process string data in discrete 64-bit chunks
    for block_num, i in enumerate(range(0, len(bit_string), 64)):
        block = bit_string[i:i+64]
        print(f"\n--- Processing Block {block_num} ('{padded_text[block_num*8:(block_num+1)*8]}') ---")
        
        # Stage 1: Encrypt with Key 1
        stage1 = des_block_operation(block, first_16_round_keys, "ENCRYPT", block_num)
        print(f"  -> Stage 1 (Enc K1) Output: {stage1[:16]}...{stage1[-16:]}")
        
        # Stage 2: Decrypt with Key 2
        stage2 = des_block_operation(stage1, second_16_round_keys, "DECRYPT", block_num)
        print(f"  -> Stage 2 (Dec K2) Output: {stage2[:16]}...{stage2[-16:]}")
        
        # Stage 3: Encrypt with Key 3
        stage3 = des_block_operation(stage2, third_16_round_keys, "ENCRYPT", block_num)
        print(f"  -> Stage 3 (Enc K3) Output: {stage3[:16]}...{stage3[-16:]}")
        
        ciphertext_bits += stage3
        
    return ciphertext_bits

def triple_des_decrypt(ciphertext_bits):
    """Reverses 3DES by decrypting with K3, encrypting with K2, decrypting with K1."""
    decrypted_bits = ""
    
    for block_num, i in enumerate(range(0, len(ciphertext_bits), 64)):
        block = ciphertext_bits[i:i+64]
        
        # Reverse Stage 3: Decrypt with Key 3
        stage3_rev = des_block_operation(block, third_16_round_keys, "DECRYPT", block_num)
        
        # Reverse Stage 2: Encrypt with Key 2
        stage2_rev = des_block_operation(stage3_rev, second_16_round_keys, "ENCRYPT", block_num)
        
        # Reverse Stage 1: Decrypt with Key 1
        stage1_rev = des_block_operation(stage2_rev, first_16_round_keys, "DECRYPT", block_num)
        
        decrypted_bits += stage1_rev
        
    padded_output_text = bit_string_to_text(decrypted_bits)
    return pkcs7_unpad(padded_output_text)

# ==============================================================================
# EXECUTION SIMULATION RUNNER
# ==============================================================================
if __name__ == "__main__":
    plaintext = "Hello 3DES Encryption"
    print(f"Original Plaintext Target: '{plaintext}'")
    print(f"Plaintext Length: {len(plaintext)} characters\n")
    
    # Run the Encryption Pipeline
    encrypted_bitstream = triple_des_encrypt(plaintext)
    
    print("\n==============================================================================")
    print("3DES EXECUTION COMPLETE")
    print("==============================================================================")
    print(f"Final Ciphertext Payload (Binary Stream):\n{encrypted_bitstream}")
    print(f"Ciphertext Length: {len(encrypted_bitstream)} bits ({len(encrypted_bitstream) // 64} total blocks)\n")
    
    # Run Decryption Verification Pipeline to prove absolute integrity
    recovered_text = triple_des_decrypt(encrypted_bitstream)
    print(f"Verified Decrypted Text Recovery: '{recovered_text}'")