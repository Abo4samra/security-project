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
    keyword = keyword.upper().replace("J", "I")  # Replace 'J' with 'I'
    seen = set()

    for char in keyword:
        if char not in seen and char in alphabet:
            key_matrix.append(char)
            seen.add(char)

    for char in alphabet:
        if char not in seen:
            key_matrix.append(char)
            seen.add(char) # Bug Fix: Need to add to seen here too

    return [key_matrix[i:i+5] for i in range(0, 25, 5)]

def playfair_encrypt(plaintext, keyword="KEYWORD"):
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
        final_plaintext += plaintext[i]
        if i + 2 < len(plaintext) and plaintext[i] == plaintext[i+2] and plaintext[i+1] == 'X':
            i += 2 # Skip the X and the repeated char
        else:
            i += 1
    if final_plaintext.endswith('X') and len(final_plaintext) % 2 == 1: # check trailing X likely padding
         final_plaintext = final_plaintext[:-1]


    return final_plaintext

# --- Polyalphabetic (Vigenere) ---
def polyalphabetic_encrypt(plaintext, keyword="KEY"):
    plaintext = plaintext.upper().replace(" ", "")
    if not plaintext: return ""
    keyword = keyword.upper()
    if not keyword: keyword = "KEY" # Default if empty
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
    keyword = keyword.upper()
    if not keyword: keyword = "KEY" # Default if empty
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
def transposition_encrypt(plaintext, key="KEY"):
    if not key: key = "KEY" # Default if empty
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    plaintext = plaintext.replace(" ", "").upper()
    if not plaintext: return ""
    num_cols = len(key)
    num_rows = (len(plaintext) + num_cols - 1) // num_cols

    # Pad plaintext if needed
    padding_len = num_rows * num_cols - len(plaintext)
    plaintext += 'X' * padding_len # Using 'X' for padding

    grid = [["" for _ in range(num_cols)] for _ in range(num_rows)]

    idx = 0
    for row in range(num_rows):
        for col in range(num_cols):
            grid[row][col] = plaintext[idx]
            idx += 1

    ciphertext = ""
    for col in key_order:
        for row in range(num_rows):
            ciphertext += grid[row][col]

    return ciphertext

def transposition_decrypt(ciphertext, key="KEY"):
    if not key: key = "KEY" # Default if empty
    if not ciphertext: return ""
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    num_cols = len(key)
    num_rows = (len(ciphertext) + num_cols - 1) // num_cols
    num_full_cols = len(ciphertext) % num_cols
    if num_full_cols == 0 and len(ciphertext) > 0:
        num_full_cols = num_cols

    grid = [["" for _ in range(num_cols)] for _ in range(num_rows)]
    key_order_map = {order_index: original_index for original_index, order_index in enumerate(key_order)}


    idx = 0
    # Determine column lengths
    col_lengths = [num_rows] * num_cols
    # Calculate shaded cells for irregular grids
    num_shaded_cells = num_cols * num_rows - len(ciphertext)
    shaded_cols = sorted(key_order, reverse=True)[:num_shaded_cells] # Columns that are shorter

    for col_key_index in key_order: # Iterate in the order columns are read
        rows_in_this_col = num_rows
        original_col_index = key_order.index(col_key_index) # Find where this column index is in the sorted list

        # Adjust row count for columns that might be shorter in non-perfect rectangles
        if original_col_index >= (num_cols - num_shaded_cells) :
             rows_in_this_col -=1


        for row in range(rows_in_this_col):
             if idx < len(ciphertext):
                 grid[row][col_key_index] = ciphertext[idx] # Place char using original column index
                 idx += 1


    plaintext = ""
    for row in range(num_rows):
        for col in range(num_cols):
            plaintext += grid[row][col]


    # Attempt to remove trailing padding 'X' - may not be perfect
    # A better way would be to store original length or use unambiguous padding
    original_len_estimate = len(ciphertext)
    while plaintext.endswith('X') and len(plaintext) > original_len_estimate - num_cols : # Heuristic
         plaintext = plaintext[:-1]


    return plaintext.strip()


# --- Rail Fence ---
def rail_fence_encrypt(plaintext, rails=3):
    plaintext = plaintext.replace(" ", "").upper()
    if not plaintext or rails <= 1: return plaintext # No encryption if no text or 1 rail

    rail_matrix = [""] * rails
    direction = 1
    row = 0

    for char in plaintext:
        rail_matrix[row] += char
        row += direction
        if row == rails - 1 or row == 0:
            direction *= -1

    return "".join(rail_matrix)

def rail_fence_decrypt(ciphertext, rails=3):
    ciphertext = ciphertext.replace(" ", "").upper()
    if not ciphertext or rails <= 1: return ciphertext

    text_len = len(ciphertext)
    rail_lengths = [0] * rails
    direction = 1
    row = 0

    # Calculate the length of each rail
    for _ in range(text_len):
        rail_lengths[row] += 1
        row += direction
        if row == rails - 1 or row == 0:
            direction *= -1

    # Build the rails with ciphertext characters
    rail_matrix = []
    start = 0
    for length in rail_lengths:
        rail_matrix.append(list(ciphertext[start : start + length]))
        start += length

    # Read off the plaintext in zigzag pattern
    plaintext = ""
    direction = 1
    row = 0
    rail_indices = [0] * rails

    for _ in range(text_len):
        plaintext += rail_matrix[row][rail_indices[row]]
        rail_indices[row] += 1
        row += direction
        if row == rails - 1 or row == 0:
            direction *= -1

    return plaintext

# --- RSA (Simplified - NOT SECURE FOR REAL USE) ---
def rsa_encrypt(plaintext, p=61, q=53, e=17):
    """
    Simplified RSA encryption. Encrypts ASCII value of each character.
    p, q: Small prime numbers (hardcoded for demonstration).
    e: Public exponent (hardcoded).
    Returns ciphertext as space-separated numbers.
    WARNING: Not cryptographically secure!
    """
    if not isinstance(p, int) or not isinstance(q, int) or not isinstance(e, int):
        return "ERROR: p, q, e must be integers." # Basic type check

    # Basic primality test (not robust for large numbers)
    def is_prime(n):
        if n < 2: return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0: return False
        return True

    # Very basic validation - real RSA needs much stronger checks
    if not (is_prime(p) and is_prime(q)):
         return f"ERROR: p={p} or q={q} not prime (basic check)."
    if p == q:
         return "ERROR: p and q cannot be equal."

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
             return f"ERROR: Character '{char}' (ASCII {m}) cannot be encrypted with n={n}."
        c = pow(m, e, n) # Efficiently calculates (m^e) % n
        ciphertext_nums.append(str(c))

    return " ".join(ciphertext_nums) # Return space-separated numbers

def rsa_decrypt(ciphertext_str, p=61, q=53, e=17):
    """
    Simplified RSA decryption. Decrypts space-separated numbers to text.
    Uses the same hardcoded p, q, e to derive the private key d.
    WARNING: Not cryptographically secure!
    """
    if not ciphertext_str: return ""
    if not isinstance(p, int) or not isinstance(q, int) or not isinstance(e, int):
        return "ERROR: p, q, e must be integers."

    # Basic primality test (not robust for large numbers)
    def is_prime(n):
        if n < 2: return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0: return False
        return True

    # Very basic validation
    if not (is_prime(p) and is_prime(q)): return f"ERROR: p={p} or q={q} not prime (basic check)."
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
        m = pow(c, d, n) # Efficiently calculates (c^d) % n
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
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i] # Swap
        K = S[(S[i] + S[j]) % 256]
        yield K

def rc4_encrypt_decrypt(text, key_str="RC4KEY"):
    """RC4 encryption/decryption function (XOR operation is symmetric)."""
    if not key_str: key_str = "RC4KEY" # Default if empty
    try:
        S = rc4_ksa(key_str)
        keystream = rc4_prga(S)
        result_bytes = bytes([b ^ next(keystream) for b in text])
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
root.title("Encryption/Decryption App")
# Increased height to accommodate new rows
root.geometry("800x275") # Adjusted height

# Create variables for input/output fields
playfair_input = tk.StringVar()
playfair_output = tk.StringVar()

polyalphabetic_input = tk.StringVar()
polyalphabetic_output = tk.StringVar()

transposition_input = tk.StringVar()
transposition_output = tk.StringVar()

rail_fence_input = tk.StringVar()
rail_fence_output = tk.StringVar()
# --- New Variables ---
rsa_input = tk.StringVar()
rsa_output = tk.StringVar()

rc4_input = tk.StringVar()
rc4_output = tk.StringVar()
# --- End New Variables ---

# Function to handle encryption for all left boxes
def encrypt_all():
    # Get inputs
    pf_in = playfair_input.get()
    poly_in = polyalphabetic_input.get()
    trans_in = transposition_input.get()
    rail_in = rail_fence_input.get()
    rsa_in = rsa_input.get()
    rc4_in = rc4_input.get()

    # Perform encryption - using default keys/params for simplicity here
    # TODO: Add entry fields for keys/params if desired
    playfair_output.set(playfair_encrypt(pf_in))
    polyalphabetic_output.set(polyalphabetic_encrypt(poly_in))
    transposition_output.set(transposition_encrypt(trans_in))
    rail_fence_output.set(rail_fence_encrypt(rail_in))
    rsa_output.set(rsa_encrypt(rsa_in)) # Using default p, q, e
    rc4_output.set(rc4_encrypt(rc4_in)) # Using default key

# Function to handle decryption for all right boxes
def decrypt_all():
    # Get inputs (from the output fields)
    pf_out = playfair_output.get()
    poly_out = polyalphabetic_output.get()
    trans_out = transposition_output.get()
    rail_out = rail_fence_output.get()
    rsa_out = rsa_output.get()
    rc4_out = rc4_output.get()

    # Perform decryption - using default keys/params for simplicity here
    playfair_input.set(playfair_decrypt(pf_out))
    polyalphabetic_input.set(polyalphabetic_decrypt(poly_out))
    transposition_input.set(transposition_decrypt(trans_out))
    rail_fence_input.set(rail_fence_decrypt(rail_out))
    rsa_input.set(rsa_decrypt(rsa_out)) # Using default p, q, e
    rc4_input.set(rc4_decrypt(rc4_out)) # Using default key

# --- GUI Layout ---
label_font = ("Arial", 12)
entry_font = ("Arial", 10)
entry_width = 40
padx_val = 10
pady_val = 5 # Reduced vertical padding slightly

# Row 0: Playfair
tk.Label(root, text="Playfair", font=label_font).grid(row=0, column=0, padx=padx_val, pady=pady_val, sticky="w")
tk.Entry(root, textvariable=playfair_input, width=entry_width, font=entry_font).grid(row=0, column=1, padx=padx_val, pady=pady_val)
tk.Entry(root, textvariable=playfair_output, width=entry_width, font=entry_font).grid(row=0, column=2, padx=padx_val, pady=pady_val)

# Row 1: Polyalphabetic
tk.Label(root, text="Polyalphabetic", font=label_font).grid(row=1, column=0, padx=padx_val, pady=pady_val, sticky="w")
tk.Entry(root, textvariable=polyalphabetic_input, width=entry_width, font=entry_font).grid(row=1, column=1, padx=padx_val, pady=pady_val)
tk.Entry(root, textvariable=polyalphabetic_output, width=entry_width, font=entry_font).grid(row=1, column=2, padx=padx_val, pady=pady_val)

# Row 2: Transposition
tk.Label(root, text="Transposition", font=label_font).grid(row=2, column=0, padx=padx_val, pady=pady_val, sticky="w")
tk.Entry(root, textvariable=transposition_input, width=entry_width, font=entry_font).grid(row=2, column=1, padx=padx_val, pady=pady_val)
tk.Entry(root, textvariable=transposition_output, width=entry_width, font=entry_font).grid(row=2, column=2, padx=padx_val, pady=pady_val)

# Row 3: Rail Fence
tk.Label(root, text="Rail Fence", font=label_font).grid(row=3, column=0, padx=padx_val, pady=pady_val, sticky="w")
tk.Entry(root, textvariable=rail_fence_input, width=entry_width, font=entry_font).grid(row=3, column=1, padx=padx_val, pady=pady_val)
tk.Entry(root, textvariable=rail_fence_output, width=entry_width, font=entry_font).grid(row=3, column=2, padx=padx_val, pady=pady_val)

# --- Row 4: RSA ---
tk.Label(root, text="RSA (Simple)", font=label_font).grid(row=4, column=0, padx=padx_val, pady=pady_val, sticky="w")
tk.Entry(root, textvariable=rsa_input, width=entry_width, font=entry_font).grid(row=4, column=1, padx=padx_val, pady=pady_val)
tk.Entry(root, textvariable=rsa_output, width=entry_width, font=entry_font).grid(row=4, column=2, padx=padx_val, pady=pady_val)

# --- Row 5: RC4 ---
tk.Label(root, text="RC4", font=label_font).grid(row=5, column=0, padx=padx_val, pady=pady_val, sticky="w")
tk.Entry(root, textvariable=rc4_input, width=entry_width, font=entry_font).grid(row=5, column=1, padx=padx_val, pady=pady_val)
tk.Entry(root, textvariable=rc4_output, width=entry_width, font=entry_font).grid(row=5, column=2, padx=padx_val, pady=pady_val)

# --- Row 6: Buttons ---
button_pady = 15
tk.Button(root, text="Encrypt All", command=encrypt_all, font=label_font, width=15).grid(row=6, column=1, pady=button_pady)
tk.Button(root, text="Decrypt All", command=decrypt_all, font=label_font, width=15).grid(row=6, column=2, pady=button_pady)

# Configure grid weights for resizing (optional but good practice)
root.grid_columnconfigure(0, weight=0) # Label column fixed width
root.grid_columnconfigure(1, weight=1) # Input column expands
root.grid_columnconfigure(2, weight=1) # Output column expands

# Start the Tkinter event loop
root.mainloop()