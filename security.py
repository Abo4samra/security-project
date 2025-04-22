import tkinter as tk
import math
import random
import binascii

# ====================
# HELPER FUNCTIONS (for RSA)
# ====================

def gcd(a, b):
    """Calculates the Greatest Common Divisor of a and b."""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Computes integers x, y such that ax + by = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y

def modInverse(a, m):
    """Calculates the modular multiplicative inverse of a modulo m."""
    d, x, y = extended_gcd(a, m)
    if d != 1:
        # Modular inverse does not exist
        # In a real scenario, you'd pick a different 'e' or primes
        raise ValueError("Modular inverse does not exist")
    return x % m

# ====================
# ENCRYPTION/DECRYPTION FUNCTIONS
# ====================

# --- Playfair ---
def generate_playfair_key(keyword):
    key_matrix = []
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 'J' is omitted
    # Use a default if keyword is empty, ensure it's processed correctly
    processed_keyword = (keyword or "KEYWORD").upper().replace("J", "I")
    seen = set()

    for char in processed_keyword:
        if char not in seen and char in alphabet:
            key_matrix.append(char)
            seen.add(char)

    for char in alphabet:
        if char not in seen:
            key_matrix.append(char)
            seen.add(char) # Bug Fix: Need to add to seen here too

    return [key_matrix[i:i+5] for i in range(0, 25, 5)]

def playfair_encrypt(plaintext, keyword="KEYWORD"):
    # Handle potentially empty keyword by defaulting inside generate_playfair_key
    key_matrix = generate_playfair_key(keyword)
    plaintext = plaintext.upper().replace("J", "I").replace(" ", "")
    if not plaintext: return "" # Handle empty input
    ciphertext = ""
    digraphs = []

    # Prepare digraphs
    i = 0
    while i < len(plaintext):
        a = plaintext[i]
        if i + 1 == len(plaintext):
            b = 'X' # Pad if odd length
            i += 1
        else:
            b = plaintext[i+1]
            if a == b:
                b = 'X' # Insert padding if letters are same
                i += 1 # Process only 'a' this iteration, 'b' becomes next 'a'
            else:
                i += 2
        digraphs.append(a + b)

    # Encrypt digraphs
    for pair in digraphs:
        a, b = pair[0], pair[1]
        pos_a = None
        pos_b = None
        for r_idx, row in enumerate(key_matrix):
            for c_idx, char in enumerate(row):
                if char == a: pos_a = (r_idx, c_idx)
                if char == b: pos_b = (r_idx, c_idx)
        if pos_a is None or pos_b is None: continue # Should not happen with valid input

        if pos_a[0] == pos_b[0]:  # Same row
            ciphertext += key_matrix[pos_a[0]][(pos_a[1] + 1) % 5]
            ciphertext += key_matrix[pos_b[0]][(pos_b[1] + 1) % 5]
        elif pos_a[1] == pos_b[1]:  # Same column
            ciphertext += key_matrix[(pos_a[0] + 1) % 5][pos_a[1]]
            ciphertext += key_matrix[(pos_b[0] + 1) % 5][pos_b[1]]
        else:  # Rectangle
            ciphertext += key_matrix[pos_a[0]][pos_b[1]]
            ciphertext += key_matrix[pos_b[0]][pos_a[1]]

    return ciphertext

def playfair_decrypt(ciphertext, keyword="KEYWORD"):
    # Handle potentially empty keyword by defaulting inside generate_playfair_key
    key_matrix = generate_playfair_key(keyword)
    ciphertext = ciphertext.upper().replace(" ", "")
    if not ciphertext or len(ciphertext) % 2 != 0: return "" # Handle empty/odd length input
    plaintext = ""

    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        pos_a = None
        pos_b = None
        for r_idx, row in enumerate(key_matrix):
            for c_idx, char in enumerate(row):
                if char == a: pos_a = (r_idx, c_idx)
                if char == b: pos_b = (r_idx, c_idx)
        if pos_a is None or pos_b is None: continue # Should not happen

        if pos_a[0] == pos_b[0]:  # Same row
            plaintext += key_matrix[pos_a[0]][(pos_a[1] - 1) % 5]
            plaintext += key_matrix[pos_b[0]][(pos_b[1] - 1) % 5]
        elif pos_a[1] == pos_b[1]:  # Same column
            plaintext += key_matrix[(pos_a[0] - 1) % 5][pos_a[1]]
            plaintext += key_matrix[(pos_b[0] - 1) % 5][pos_b[1]]
        else:  # Rectangle
            plaintext += key_matrix[pos_a[0]][pos_b[1]]
            plaintext += key_matrix[pos_b[0]][pos_a[1]]

    # Basic attempt to remove padding 'X' - might remove legitimate 'X's
    # A more robust solution would involve context or marking padding.
    final_plaintext = ""
    i = 0
    while i < len(plaintext):
      # Check for X used as padding between identical letters
      if i + 2 < len(plaintext) and plaintext[i] == plaintext[i+2] and plaintext[i+1] == 'X':
          final_plaintext += plaintext[i] # Keep the first letter
          i += 2 # Skip the 'X' and the repeated second letter
      # Check for final X used as padding for odd length
      elif i == len(plaintext) - 1 and plaintext[i] == 'X':
           # Check if the pair before it was NOT two identical letters
           # (if it was, the 'X' was likely padding for identity, not length)
           if not (i > 1 and plaintext[i-2] == plaintext[i] and plaintext[i-1] == 'X'):
                # If the last char is X and likely padding for length, discard it
                i += 1 # Effectively skips adding the last X
           else:
                # If the pattern indicates X was for identity, keep it (less common)
                final_plaintext += plaintext[i]
                i += 1
      else:
          final_plaintext += plaintext[i]
          i += 1

    # If the loop finished and the last character added was an X,
    # and the original length was odd, it might be trailing padding.
    # This logic is complex and imperfect.
    # A truly reliable system needs a way to distinguish padding 'X' from message 'X'.
    if final_plaintext.endswith('X') and len(plaintext) % 2 != 0:
         # A slightly better heuristic: only remove if the second to last isn't the same
         # as the third to last (less likely to be X padding identical letters)
        if len(final_plaintext) < 3 or final_plaintext[-3] != final_plaintext[-1]:
            # Check context to be more sure it's padding
            # For this simple tool, we'll remove it if it *looks* like length padding
            # A more advanced check could see if removing it creates a valid word, etc.
            pass # Let's keep the heuristic removal simple for now, it's tricky
            # final_plaintext = final_plaintext[:-1] # Re-enable if simple removal is desired

    return final_plaintext


# --- Polyalphabetic (Vigenere) ---
def polyalphabetic_encrypt(plaintext, keyword="KEY"):
    plaintext = plaintext.upper().replace(" ", "")
    if not plaintext: return ""
    keyword = (keyword or "KEY").upper() # Default if empty
    ciphertext = ""
    keyword_len = len(keyword)

    for i, p_char in enumerate(plaintext):
        if p_char.isalpha():
            k_char = keyword[i % keyword_len]
            shift = ord(k_char) - ord('A')
            ciphertext += chr((ord(p_char) - ord('A') + shift) % 26 + ord('A'))
        else:
            ciphertext += p_char # Keep non-alpha chars (though preprocessing removes spaces)

    return ciphertext

def polyalphabetic_decrypt(ciphertext, keyword="KEY"):
    ciphertext = ciphertext.upper().replace(" ", "")
    if not ciphertext: return ""
    keyword = (keyword or "KEY").upper() # Default if empty
    plaintext = ""
    keyword_len = len(keyword)

    for i, c_char in enumerate(ciphertext):
        if c_char.isalpha():
            k_char = keyword[i % keyword_len]
            shift = ord(k_char) - ord('A')
            plaintext += chr((ord(c_char) - ord('A') - shift + 26) % 26 + ord('A')) # Added +26 for correct negative modulo
        else:
            plaintext += c_char # Keep non-alpha chars

    return plaintext

# --- Transposition ---
# Using simplified key='3142' style transposition for easier key entry
def get_transposition_order(key):
    """ Converts a numeric key string like '3142' into the column order [1, 3, 0, 2] """
    if not key or not key.isdigit():
        key = "3142" # Default key if invalid or empty
    # Create pairs of (digit, original_index)
    key_pairs = [(int(digit), i) for i, digit in enumerate(key)]
    # Sort by the digit, maintaining original index
    key_pairs.sort()
    # Return just the original indices in the sorted order
    return [index for digit, index in key_pairs]

def transposition_encrypt(plaintext, key="3142"):
    key_order = get_transposition_order(key)
    num_cols = len(key_order)
    if num_cols == 0: return plaintext # Handle case where key becomes invalid/empty

    plaintext = plaintext.replace(" ", "").upper()
    if not plaintext: return ""
    num_rows = (len(plaintext) + num_cols - 1) // num_cols

    # Pad plaintext if needed
    padding_len = num_rows * num_cols - len(plaintext)
    plaintext += 'X' * padding_len # Using 'X' for padding

    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]

    idx = 0
    for row in range(num_rows):
        for col in range(num_cols):
            if idx < len(plaintext): # Ensure we don't go out of bounds
                grid[row][col] = plaintext[idx]
                idx += 1

    ciphertext = ""
    for col_index in key_order: # Read based on the derived numeric order
        for row in range(num_rows):
            ciphertext += grid[row][col_index]

    return ciphertext

def transposition_decrypt(ciphertext, key="3142"):
    key_order = get_transposition_order(key)
    num_cols = len(key_order)
    if num_cols == 0 or not ciphertext : return ciphertext # Handle invalid key or empty text

    text_len = len(ciphertext)
    num_rows = (text_len + num_cols - 1) // num_cols
    num_shaded_cells = (num_cols * num_rows) - text_len

    # Determine which columns in the *original* grid layout were shorter
    # These correspond to the columns read *last* according to the key order
    cols_in_read_order = key_order # Columns ordered by key [1, 3, 0, 2] for key '3142'
    shorter_col_indices = cols_in_read_order[num_cols - num_shaded_cells:] # The last 'num_shaded_cells' columns read are shorter

    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]

    idx = 0
    for col_index in key_order: # Iterate through columns in the reading order
        rows_in_this_col = num_rows
        if col_index in shorter_col_indices:
            rows_in_this_col -= 1

        for row in range(rows_in_this_col):
            if idx < text_len:
                grid[row][col_index] = ciphertext[idx]
                idx += 1

    plaintext = ""
    for row in range(num_rows):
        for col in range(num_cols):
            plaintext += grid[row][col]

    # Remove padding 'X' based on original length before padding
    original_len = text_len
    padded_len = num_cols*num_rows
    num_padding_chars = padded_len - original_len

    # If the last 'num_padding_chars' are all 'X', remove them
    if num_padding_chars > 0 and plaintext.endswith('X' * num_padding_chars):
         plaintext = plaintext[:-num_padding_chars]
    # Basic removal of trailing 'X' if the above fails (less reliable)
    # elif plaintext.endswith('X'):
    #     plaintext = plaintext.rstrip('X')


    return plaintext


# --- Rail Fence ---
def rail_fence_encrypt(plaintext, rails=3):
    # Ensure rails is an integer > 1
    try:
        rails = int(rails)
        if rails <= 1: rails = 3 # Default if invalid
    except ValueError:
        rails = 3 # Default if not convertible to int

    plaintext = plaintext.replace(" ", "").upper()
    if not plaintext: return plaintext # No encryption if no text

    rail_matrix = [""] * rails
    direction = 1
    row = 0

    for char in plaintext:
        rail_matrix[row] += char
        # Change direction at top or bottom rail
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    return "".join(rail_matrix)

def rail_fence_decrypt(ciphertext, rails=3):
     # Ensure rails is an integer > 1
    try:
        rails = int(rails)
        if rails <= 1: rails = 3 # Default if invalid
    except ValueError:
        rails = 3 # Default if not convertible to int

    ciphertext = ciphertext.replace(" ", "").upper()
    if not ciphertext: return ciphertext

    text_len = len(ciphertext)
    rail_lengths = [0] * rails
    direction = 1
    row = 0

    # Simulate the fence writing to determine lengths
    for _ in range(text_len):
        rail_lengths[row] += 1
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    # Build the rails with ciphertext characters
    rail_matrix = []
    start = 0
    for length in rail_lengths:
        # Take the correct slice from ciphertext for this rail
        rail_matrix.append(list(ciphertext[start : start + length]))
        start += length

    # Read off the plaintext in zigzag pattern using rail counters
    plaintext = ""
    direction = 1
    row = 0
    rail_indices = [0] * rails # Track current read position in each rail list

    for _ in range(text_len):
        # Take the next character from the *correct* rail list
        plaintext += rail_matrix[row][rail_indices[row]]
        rail_indices[row] += 1 # Increment the index for the rail we just read from

        # Move to the next rail for the next character
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    return plaintext


# --- RSA (Simplified - NOT SECURE FOR REAL USE) ---
def rsa_encrypt(plaintext, p_str="61", q_str="53", e_str="17"):
    """
    Simplified RSA encryption. Encrypts ASCII value of each character.
    p_str, q_str, e_str: String inputs for parameters.
    Returns ciphertext as space-separated numbers or ERROR message.
    WARNING: Not cryptographically secure!
    """
    try:
        p = int(p_str)
        q = int(q_str)
        e = int(e_str)
    except ValueError:
        return "ERROR: p, q, e must be valid integers."

    # Basic primality test (not robust for large numbers)
    def is_prime(n):
        if n < 2: return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0: return False
        return True

    # Very basic validation - real RSA needs much stronger checks
    if not is_prime(p): return f"ERROR: p={p} not prime (basic check)."
    if not is_prime(q): return f"ERROR: q={q} not prime (basic check)."
    if p == q: return "ERROR: p and q cannot be equal."

    n = p * q
    phi = (p - 1) * (q - 1)

    if gcd(e, phi) != 1:
        return f"ERROR: e={e} is not coprime to phi={phi}."
    if not (1 < e < phi):
        return f"ERROR: e={e} must be > 1 and < phi={phi}."

    # Encrypt each character's ASCII value
    ciphertext_nums = []
    for char in plaintext:
        m = ord(char) # Convert char to ASCII integer
        if m >= n:
             # This simple version can't handle chars whose ordinals >= n
             return f"ERROR: Character '{char}' (ASCII {m}) cannot be encrypted with n={n} (p={p}, q={q})."
        try:
            c = pow(m, e, n) # Efficiently calculates (m^e) % n
            ciphertext_nums.append(str(c))
        except ValueError as ve:
             return f"ERROR during exponentiation: {ve}"


    return " ".join(ciphertext_nums) # Return space-separated numbers

def rsa_decrypt(ciphertext_str, p_str="61", q_str="53", e_str="17"):
    """
    Simplified RSA decryption. Decrypts space-separated numbers to text.
    Uses the p, q, e strings to derive the private key d.
    WARNING: Not cryptographically secure!
    """
    if not ciphertext_str: return ""
    try:
        p = int(p_str)
        q = int(q_str)
        e = int(e_str)
    except ValueError:
        return "ERROR: p, q, e must be valid integers."


    # Basic primality test (not robust for large numbers)
    def is_prime(n):
        if n < 2: return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0: return False
        return True

    # Very basic validation
    if not is_prime(p): return f"ERROR: p={p} not prime (basic check)."
    if not is_prime(q): return f"ERROR: q={q} not prime (basic check)."
    if p == q: return "ERROR: p and q cannot be equal."

    n = p * q
    phi = (p - 1) * (q - 1)

    if gcd(e, phi) != 1: return f"ERROR: e={e} is not coprime to phi={phi}."
    if not (1 < e < phi): return f"ERROR: e={e} must be > 1 and < phi={phi}."

    try:
        d = modInverse(e, phi) # Calculate private exponent
    except ValueError:
        return f"ERROR: Cannot compute modular inverse for e={e}, phi={phi}."

    try:
        # Split the input string into numbers
        ciphertext_nums = [int(num) for num in ciphertext_str.split()]
    except ValueError:
        return "ERROR: Invalid ciphertext format (must be space-separated integers)."

    plaintext = ""
    for c in ciphertext_nums:
        if c >= n:
             return f"ERROR: Ciphertext value {c} is >= n={n}."
        try:
            m = pow(c, d, n) # Efficiently calculates (c^d) % n
        except ValueError as ve:
             return f"ERROR during exponentiation: {ve}"

        try:
             plaintext += chr(m) # Convert back to character
        except ValueError:
             # Handle cases where decrypted value isn't a valid ASCII/Unicode char
             plaintext += f"[ERR:{m}]"

    return plaintext

# --- RC4 ---
def rc4_ksa(key_str):
    """Key Scheduling Algorithm for RC4."""
    key = key_str.encode('utf-8') # Convert key string to bytes
    key_length = len(key)
    if key_length == 0: # Handle empty key case
        key = b"RC4KEY" # Use a default key if empty
        key_length = len(key)

    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i] # Swap
    return S

def rc4_prga(S):
    """Pseudo-Random Generation Algorithm (PRGA) for RC4 - yields keystream bytes."""
    i = 0
    j = 0
    # Need a copy so the original S in the caller isn't modified if PRGA is reused
    S_copy = S[:]
    while True:
        i = (i + 1) % 256
        j = (j + S_copy[i]) % 256
        S_copy[i], S_copy[j] = S_copy[j], S_copy[i] # Swap using the copy
        K = S_copy[(S_copy[i] + S_copy[j]) % 256]
        yield K

def rc4_encrypt_decrypt(text_bytes, key_str="RC4KEY"):
    """RC4 encryption/decryption function (XOR operation is symmetric)."""
    # Ensure key is not empty, provide default if needed
    if not key_str: key_str = "RC4KEY"
    try:
        S = rc4_ksa(key_str)
        keystream = rc4_prga(S)
        result_bytes = bytes([b ^ next(keystream) for b in text_bytes])
        return result_bytes
    except Exception as e:
        print(f"RC4 Error: {e}") # Log error
        return None # Indicate failure

def rc4_encrypt(plaintext, key_str="RC4KEY"):
    """RC4 Encrypt: text -> hex string"""
    if not plaintext: return ""
    try:
        plaintext_bytes = plaintext.encode('utf-8')
        encrypted_bytes = rc4_encrypt_decrypt(plaintext_bytes, key_str)
        if encrypted_bytes is None: return "ERROR: RC4 encryption failed."
        # Represent binary data as hex string for display
        return binascii.hexlify(encrypted_bytes).decode('utf-8')
    except Exception as e:
        return f"ERROR: {e}"


def rc4_decrypt(ciphertext_hex, key_str="RC4KEY"):
    """RC4 Decrypt: hex string -> text"""
    if not ciphertext_hex: return ""
    try:
        # Ensure hex string has even length
        if len(ciphertext_hex) % 2 != 0:
            return "ERROR: Invalid Hex ciphertext (odd length)."
        ciphertext_bytes = binascii.unhexlify(ciphertext_hex.encode('utf-8'))
        decrypted_bytes = rc4_encrypt_decrypt(ciphertext_bytes, key_str)
        if decrypted_bytes is None: return "ERROR: RC4 decryption failed."
        # Decode bytes back to string, handle potential errors
        return decrypted_bytes.decode('utf-8', errors='replace')
    except binascii.Error:
        return "ERROR: Invalid Hex ciphertext format."
    except Exception as e:
        return f"ERROR: {e}"


# ====================
# TKINTER GUI SETUP
# ====================

# Create the main window
root = tk.Tk()
root.title("Cipher Suite")
# Increased width and height to accommodate new fields and rows
root.geometry("1100x280") # Adjusted width and height


# --- StringVars for Inputs/Outputs/Keys ---
# Playfair
playfair_input = tk.StringVar()
playfair_output = tk.StringVar()
playfair_keyword_var = tk.StringVar(value="KEYWORD") # Added for Playfair key

# Polyalphabetic (Vigenere) - Added key var
polyalphabetic_input = tk.StringVar()
polyalphabetic_output = tk.StringVar()
polyalphabetic_key_var = tk.StringVar(value="KEY")

# Transposition - Added key var (using numeric string style)
transposition_input = tk.StringVar()
transposition_output = tk.StringVar()
transposition_key_var = tk.StringVar(value="3142") # Example numeric key

# Rail Fence - Added key var (number of rails)
rail_fence_input = tk.StringVar()
rail_fence_output = tk.StringVar()
rail_fence_key_var = tk.StringVar(value="3") # Rails key

# RSA - Added parameter vars
rsa_input = tk.StringVar()
rsa_output = tk.StringVar()
rsa_p_var = tk.StringVar(value="61")
rsa_q_var = tk.StringVar(value="53")
rsa_e_var = tk.StringVar(value="17")

# RC4 - Added key var
rc4_input = tk.StringVar()
rc4_output = tk.StringVar()
rc4_key_var = tk.StringVar(value="RC4KEY")


# --- Encryption/Decryption Handlers ---
def encrypt_all():
    # Get Playfair inputs
    pf_in = playfair_input.get()
    pf_key = playfair_keyword_var.get()
    playfair_output.set(playfair_encrypt(pf_in, keyword=pf_key))

    # Get Polyalphabetic inputs
    poly_in = polyalphabetic_input.get()
    poly_key = polyalphabetic_key_var.get()
    polyalphabetic_output.set(polyalphabetic_encrypt(poly_in, keyword=poly_key))

    # Get Transposition inputs
    trans_in = transposition_input.get()
    trans_key = transposition_key_var.get()
    transposition_output.set(transposition_encrypt(trans_in, key=trans_key))

    # Get Rail Fence inputs
    rail_in = rail_fence_input.get()
    rail_key = rail_fence_key_var.get() # Get rails value
    rail_fence_output.set(rail_fence_encrypt(rail_in, rails=rail_key)) # Pass rails key

    # Get RSA inputs
    rsa_in = rsa_input.get()
    rsa_p = rsa_p_var.get()
    rsa_q = rsa_q_var.get()
    rsa_e = rsa_e_var.get()
    rsa_output.set(rsa_encrypt(rsa_in, p_str=rsa_p, q_str=rsa_q, e_str=rsa_e))

    # Get RC4 inputs
    rc4_in = rc4_input.get()
    rc4_key = rc4_key_var.get()
    rc4_output.set(rc4_encrypt(rc4_in, key_str=rc4_key))


def decrypt_all():
    # Get Playfair inputs (from output field)
    pf_out = playfair_output.get()
    pf_key = playfair_keyword_var.get() # Use the same key for decryption
    playfair_input.set(playfair_decrypt(pf_out, keyword=pf_key))

    # Get Polyalphabetic inputs
    poly_out = polyalphabetic_output.get()
    poly_key = polyalphabetic_key_var.get()
    polyalphabetic_input.set(polyalphabetic_decrypt(poly_out, keyword=poly_key))

    # Get Transposition inputs
    trans_out = transposition_output.get()
    trans_key = transposition_key_var.get()
    transposition_input.set(transposition_decrypt(trans_out, key=trans_key))

    # Get Rail Fence inputs
    rail_out = rail_fence_output.get()
    rail_key = rail_fence_key_var.get() # Get rails value
    rail_fence_input.set(rail_fence_decrypt(rail_out, rails=rail_key)) # Pass rails key

    # Get RSA inputs
    rsa_out = rsa_output.get()
    rsa_p = rsa_p_var.get()
    rsa_q = rsa_q_var.get()
    rsa_e = rsa_e_var.get()
    rsa_input.set(rsa_decrypt(rsa_out, p_str=rsa_p, q_str=rsa_q, e_str=rsa_e))

    # Get RC4 inputs
    rc4_out = rc4_output.get()
    rc4_key = rc4_key_var.get()
    rc4_input.set(rc4_decrypt(rc4_out, key_str=rc4_key))


# --- GUI Layout ---
label_font = ("Arial", 10, "bold")
entry_font = ("Arial", 10)
main_entry_width = 45 # Width for Plaintext/Ciphertext
key_entry_width = 15  # Width for Key/Parameter entries
padx_val = 5
pady_val = 3
sticky_ew = "ew" # Stretch horizontally

# --- Column Headers ---
tk.Label(root, text="Cipher", font=label_font).grid(row=0, column=0, padx=padx_val, pady=pady_val*2, sticky="w")
tk.Label(root, text="Key/Params", font=label_font).grid(row=0, column=1, padx=padx_val, pady=pady_val*2, sticky="w")
tk.Label(root, text="Plaintext", font=label_font).grid(row=0, column=2, padx=padx_val, pady=pady_val*2, sticky="w")
tk.Label(root, text="Ciphertext", font=label_font).grid(row=0, column=3, padx=padx_val, pady=pady_val*2, sticky="w")


# Row 1: Playfair
row_num = 1
tk.Label(root, text="Playfair", anchor="w").grid(row=row_num, column=0, padx=padx_val, pady=pady_val, sticky="w")
tk.Entry(root, textvariable=playfair_keyword_var, width=key_entry_width, font=entry_font).grid(row=row_num, column=1, padx=padx_val, pady=pady_val, sticky=sticky_ew)
tk.Entry(root, textvariable=playfair_input, width=main_entry_width, font=entry_font).grid(row=row_num, column=2, padx=padx_val, pady=pady_val, sticky=sticky_ew)
tk.Entry(root, textvariable=playfair_output, width=main_entry_width, font=entry_font).grid(row=row_num, column=3, padx=padx_val, pady=pady_val, sticky=sticky_ew)

# Row 2: Polyalphabetic (Vigenere)
row_num = 2
tk.Label(root, text="Vigenere", anchor="w").grid(row=row_num, column=0, padx=padx_val, pady=pady_val, sticky="w")
tk.Entry(root, textvariable=polyalphabetic_key_var, width=key_entry_width, font=entry_font).grid(row=row_num, column=1, padx=padx_val, pady=pady_val, sticky=sticky_ew)
tk.Entry(root, textvariable=polyalphabetic_input, width=main_entry_width, font=entry_font).grid(row=row_num, column=2, padx=padx_val, pady=pady_val, sticky=sticky_ew)
tk.Entry(root, textvariable=polyalphabetic_output, width=main_entry_width, font=entry_font).grid(row=row_num, column=3, padx=padx_val, pady=pady_val, sticky=sticky_ew)

# Row 3: Transposition
row_num = 3
tk.Label(root, text="Transposition", anchor="w").grid(row=row_num, column=0, padx=padx_val, pady=pady_val, sticky="w")
tk.Entry(root, textvariable=transposition_key_var, width=key_entry_width, font=entry_font).grid(row=row_num, column=1, padx=padx_val, pady=pady_val, sticky=sticky_ew)
tk.Entry(root, textvariable=transposition_input, width=main_entry_width, font=entry_font).grid(row=row_num, column=2, padx=padx_val, pady=pady_val, sticky=sticky_ew)
tk.Entry(root, textvariable=transposition_output, width=main_entry_width, font=entry_font).grid(row=row_num, column=3, padx=padx_val, pady=pady_val, sticky=sticky_ew)

# Row 4: Rail Fence
row_num = 4
tk.Label(root, text="Rail Fence (Rails)", anchor="w").grid(row=row_num, column=0, padx=padx_val, pady=pady_val, sticky="w")
tk.Entry(root, textvariable=rail_fence_key_var, width=key_entry_width, font=entry_font).grid(row=row_num, column=1, padx=padx_val, pady=pady_val, sticky=sticky_ew)
tk.Entry(root, textvariable=rail_fence_input, width=main_entry_width, font=entry_font).grid(row=row_num, column=2, padx=padx_val, pady=pady_val, sticky=sticky_ew)
tk.Entry(root, textvariable=rail_fence_output, width=main_entry_width, font=entry_font).grid(row=row_num, column=3, padx=padx_val, pady=pady_val, sticky=sticky_ew)

# --- Row 5: RSA ---
row_num = 5
tk.Label(root, text="RSA (p, q, e)", anchor="w").grid(row=row_num, column=0, padx=padx_val, pady=pady_val, sticky="w")
# Frame to hold the multiple RSA parameter entries in one column
rsa_param_frame = tk.Frame(root)
rsa_param_frame.grid(row=row_num, column=1, padx=padx_val, pady=pady_val, sticky=sticky_ew)
tk.Entry(rsa_param_frame, textvariable=rsa_p_var, width=4, font=entry_font).pack(side=tk.LEFT, padx=1)
tk.Entry(rsa_param_frame, textvariable=rsa_q_var, width=4, font=entry_font).pack(side=tk.LEFT, padx=1)
tk.Entry(rsa_param_frame, textvariable=rsa_e_var, width=4, font=entry_font).pack(side=tk.LEFT, padx=1)
tk.Entry(root, textvariable=rsa_input, width=main_entry_width, font=entry_font).grid(row=row_num, column=2, padx=padx_val, pady=pady_val, sticky=sticky_ew)
tk.Entry(root, textvariable=rsa_output, width=main_entry_width, font=entry_font).grid(row=row_num, column=3, padx=padx_val, pady=pady_val, sticky=sticky_ew)


# --- Row 6: RC4 ---
row_num = 6
tk.Label(root, text="RC4", anchor="w").grid(row=row_num, column=0, padx=padx_val, pady=pady_val, sticky="w")
tk.Entry(root, textvariable=rc4_key_var, width=key_entry_width, font=entry_font).grid(row=row_num, column=1, padx=padx_val, pady=pady_val, sticky=sticky_ew)
tk.Entry(root, textvariable=rc4_input, width=main_entry_width, font=entry_font).grid(row=row_num, column=2, padx=padx_val, pady=pady_val, sticky=sticky_ew)
tk.Entry(root, textvariable=rc4_output, width=main_entry_width, font=entry_font).grid(row=row_num, column=3, padx=padx_val, pady=pady_val, sticky=sticky_ew)


# --- Row 7: Buttons ---
button_pady = 15
button_padx = 10
button_font = ("Arial", 11, "bold")
button_width = 15

# Frame to center buttons below input/output columns
button_frame = tk.Frame(root)
# Place this frame spanning columns 2 and 3, below the last cipher row
button_frame.grid(row=row_num + 1, column=3, columnspan=2, pady=button_pady)

tk.Button(button_frame, text="Encrypt All", command=encrypt_all, font=button_font, width=button_width).pack(side=tk.LEFT, padx=button_padx)
tk.Button(button_frame, text="Decrypt All", command=decrypt_all, font=button_font, width=button_width).pack(side=tk.LEFT, padx=button_padx)


# Configure grid weights for resizing
root.grid_columnconfigure(0, weight=0) # Cipher Label column fixed width
root.grid_columnconfigure(1, weight=0) # Key/Params column fixed width (or use weight=1 if you want it to expand too)
root.grid_columnconfigure(2, weight=1) # Plaintext column expands
root.grid_columnconfigure(3, weight=1) # Ciphertext column expands

# Configure row weights (optional, allows vertical expansion if needed)
for i in range(row_num + 2): # +1 for last cipher row, +1 for button row
    root.grid_rowconfigure(i, weight=0) # Usually keep rows fixed height
# You could give the button row weight=1 if you wanted it to be pushed down on resize

# Start the Tkinter event loop
root.mainloop()