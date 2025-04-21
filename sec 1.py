import tkinter as tk

# ====================
# ENCRYPTION/DECRYPTION FUNCTIONS
# ====================

def generate_playfair_key(keyword):
    # Create a 5x5 key matrix
    key_matrix = []
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 'J' is omitted
    keyword = keyword.upper().replace("J", "I")  # Replace 'J' with 'I'
    seen = set()

    # Add keyword letters to the matrix
    for char in keyword:
        if char not in seen and char in alphabet:
            key_matrix.append(char)
            seen.add(char)

    # Add remaining alphabet letters
    for char in alphabet:
        if char not in seen:
            key_matrix.append(char)
            seen.add(char)

    # Reshape into a 5x5 matrix
    return [key_matrix[i:i+5] for i in range(0, 25, 5)]

def playfair_encrypt(plaintext, keyword="KEYWORD"):
    key_matrix = generate_playfair_key(keyword)
    plaintext = plaintext.upper().replace("J", "I").replace(" ", "")  # Prepare plaintext
    ciphertext = ""

    # Split plaintext into digraphs
    i = 0
    while i < len(plaintext):
        a = plaintext[i]
        b = plaintext[i + 1] if i + 1 < len(plaintext) else "X"  # Add padding if needed
        if a == b:
            b = "X"
            i -= 1  # Re-process the second letter
        i += 2

        # Find positions in the key matrix
        pos_a = [(row_idx, col_idx) for row_idx, row in enumerate(key_matrix) for col_idx, char in enumerate(row) if char == a][0]
        pos_b = [(row_idx, col_idx) for row_idx, row in enumerate(key_matrix) for col_idx, char in enumerate(row) if char == b][0]

        # Apply Playfair rules
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
    ciphertext = ciphertext.upper().replace(" ", "")  # Prepare ciphertext
    plaintext = ""

    # Process digraphs
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]

        # Find positions in the key matrix
        pos_a = [(row_idx, col_idx) for row_idx, row in enumerate(key_matrix) for col_idx, char in enumerate(row) if char == a][0]
        pos_b = [(row_idx, col_idx) for row_idx, row in enumerate(key_matrix) for col_idx, char in enumerate(row) if char == b][0]

        # Apply reverse Playfair rules
        if pos_a[0] == pos_b[0]:  # Same row
            plaintext += key_matrix[pos_a[0]][(pos_a[1] - 1) % 5]
            plaintext += key_matrix[pos_b[0]][(pos_b[1] - 1) % 5]
        elif pos_a[1] == pos_b[1]:  # Same column
            plaintext += key_matrix[(pos_a[0] - 1) % 5][pos_a[1]]
            plaintext += key_matrix[(pos_b[0] - 1) % 5][pos_b[1]]
        else:  # Rectangle
            plaintext += key_matrix[pos_a[0]][pos_b[1]]
            plaintext += key_matrix[pos_b[0]][pos_a[1]]

    return plaintext

def polyalphabetic_encrypt(plaintext, keyword="KEY"):
    plaintext = plaintext.upper().replace(" ", "")
    keyword = keyword.upper()
    ciphertext = ""

    # Extend the keyword to match plaintext length
    extended_keyword = (keyword * (len(plaintext) // len(keyword) + 1))[:len(plaintext)]

    for p_char, k_char in zip(plaintext, extended_keyword):
        if p_char.isalpha():
            shift = ord(k_char) - ord('A')
            ciphertext += chr((ord(p_char) - ord('A') + shift) % 26 + ord('A'))
        else:
            ciphertext += p_char  # Non-alphabetic characters are unchanged

    return ciphertext

def polyalphabetic_decrypt(ciphertext, keyword="KEY"):
    ciphertext = ciphertext.upper().replace(" ", "")
    keyword = keyword.upper()
    plaintext = ""

    # Extend the keyword to match ciphertext length
    extended_keyword = (keyword * (len(ciphertext) // len(keyword) + 1))[:len(ciphertext)]

    for c_char, k_char in zip(ciphertext, extended_keyword):
        if c_char.isalpha():
            shift = ord(k_char) - ord('A')
            plaintext += chr((ord(c_char) - ord('A') - shift) % 26 + ord('A'))
        else:
            plaintext += c_char  # Non-alphabetic characters are unchanged

    return plaintext

def transposition_encrypt(plaintext, key="KEY"):
    key_order = sorted(range(len(key)), key=lambda k: key[k])  # Sort columns by key
    plaintext = plaintext.replace(" ", "").upper()
    num_cols = len(key)
    num_rows = (len(plaintext) + num_cols - 1) // num_cols  # Calculate rows
    grid = [["" for _ in range(num_cols)] for _ in range(num_rows)]

    # Fill the grid
    idx = 0
    for row in range(num_rows):
        for col in range(num_cols):
            if idx < len(plaintext):
                grid[row][col] = plaintext[idx]
                idx += 1

    # Read columns in key order
    ciphertext = ""
    for col in key_order:
        for row in range(num_rows):
            if grid[row][col]:
                ciphertext += grid[row][col]

    return ciphertext

def transposition_decrypt(ciphertext, key="KEY"):
    key_order = sorted(range(len(key)), key=lambda k: key[k])  # Sort columns by key
    num_cols = len(key)
    num_rows = (len(ciphertext) + num_cols - 1) // num_cols  # Calculate rows
    grid = [["" for _ in range(num_cols)] for _ in range(num_rows)]

    # Fill the grid in key order
    idx = 0
    for col in key_order:
        for row in range(num_rows):
            if idx < len(ciphertext):
                grid[row][col] = ciphertext[idx]
                idx += 1

    # Read rows sequentially
    plaintext = ""
    for row in range(num_rows):
        for col in range(num_cols):
            if grid[row][col]:
                plaintext += grid[row][col]

    return plaintext.strip()

def rail_fence_encrypt(plaintext, rails=3):
    plaintext = plaintext.replace(" ", "").upper()
    rail_matrix = [["" for _ in range(len(plaintext))] for _ in range(rails)]
    direction = 1  # 1 for down, -1 for up
    row, col = 0, 0

    # Fill the rail matrix
    for char in plaintext:
        rail_matrix[row][col] = char
        row += direction
        if row == rails - 1 or row == 0:
            direction *= -1
        col += 1

    # Read the ciphertext row by row
    ciphertext = ""
    for row in rail_matrix:
        ciphertext += "".join(char for char in row if char)

    return ciphertext

def rail_fence_decrypt(ciphertext, rails=3):
    ciphertext = ciphertext.replace(" ", "").upper()
    rail_matrix = [["" for _ in range(len(ciphertext))] for _ in range(rails)]
    direction = 1  # 1 for down, -1 for up
    row, col = 0, 0

    # Mark the positions in the rail matrix
    for _ in range(len(ciphertext)):
        rail_matrix[row][col] = "*"
        row += direction
        if row == rails - 1 or row == 0:
            direction *= -1
        col += 1

    # Fill the ciphertext into the marked positions
    idx = 0
    for r in range(rails):
        for c in range(len(ciphertext)):
            if rail_matrix[r][c] == "*" and idx < len(ciphertext):
                rail_matrix[r][c] = ciphertext[idx]
                idx += 1

    # Read the plaintext in zigzag order
    plaintext = ""
    row, col = 0, 0
    direction = 1
    for _ in range(len(ciphertext)):
        plaintext += rail_matrix[row][col]
        row += direction
        if row == rails - 1 or row == 0:
            direction *= -1
        col += 1

    return plaintext

# ====================
# TKINTER GUI SETUP
# ====================

# Create the main window
root = tk.Tk()
root.title("Encryption/Decryption App")
root.geometry("800x300")  # Set the window size (width x height)

# Create variables for input/output fields
playfair_input = tk.StringVar()
playfair_output = tk.StringVar()

polyalphabetic_input = tk.StringVar()
polyalphabetic_output = tk.StringVar()

transposition_input = tk.StringVar()
transposition_output = tk.StringVar()

rail_fence_input = tk.StringVar()
rail_fence_output = tk.StringVar()

# Function to handle encryption for all left boxes
def encrypt_all():
    playfair_output.set(playfair_encrypt(playfair_input.get()))
    polyalphabetic_output.set(polyalphabetic_encrypt(polyalphabetic_input.get()))
    transposition_output.set(transposition_encrypt(transposition_input.get()))
    rail_fence_output.set(rail_fence_encrypt(rail_fence_input.get()))

# Function to handle decryption for all right boxes
def decrypt_all():
    playfair_input.set(playfair_decrypt(playfair_output.get()))
    polyalphabetic_input.set(polyalphabetic_decrypt(polyalphabetic_output.get()))
    transposition_input.set(transposition_decrypt(transposition_output.get()))
    rail_fence_input.set(rail_fence_decrypt(rail_fence_output.get()))

# Create labels, input/output fields, and buttons
tk.Label(root, text="Playfair", font=("Arial", 12)).grid(row=0, column=0, padx=20, pady=10)
tk.Entry(root, textvariable=playfair_input, width=40, font=("Arial", 10)).grid(row=0, column=1, padx=10, pady=10)
tk.Entry(root, textvariable=playfair_output, width=40, font=("Arial", 10)).grid(row=0, column=2, padx=10, pady=10)

tk.Label(root, text="Polyalphabetic", font=("Arial", 12)).grid(row=1, column=0, padx=20, pady=10)
tk.Entry(root, textvariable=polyalphabetic_input, width=40, font=("Arial", 10)).grid(row=1, column=1, padx=10, pady=10)
tk.Entry(root, textvariable=polyalphabetic_output, width=40, font=("Arial", 10)).grid(row=1, column=2, padx=10, pady=10)

tk.Label(root, text="Transposition", font=("Arial", 12)).grid(row=2, column=0, padx=20, pady=10)
tk.Entry(root, textvariable=transposition_input, width=40, font=("Arial", 10)).grid(row=2, column=1, padx=10, pady=10)
tk.Entry(root, textvariable=transposition_output, width=40, font=("Arial", 10)).grid(row=2, column=2, padx=10, pady=10)

tk.Label(root, text="Rail Fence", font=("Arial", 12)).grid(row=3, column=0, padx=20, pady=10)
tk.Entry(root, textvariable=rail_fence_input, width=40, font=("Arial", 10)).grid(row=3, column=1, padx=10, pady=10)
tk.Entry(root, textvariable=rail_fence_output, width=40, font=("Arial", 10)).grid(row=3, column=2, padx=10, pady=10)

# Add Encrypt and Decrypt buttons
tk.Button(root, text="Encrypt All", command=encrypt_all, font=("Arial", 12), width=15).grid(row=4, column=1, pady=20)
tk.Button(root, text="Decrypt All", command=decrypt_all, font=("Arial", 12), width=15).grid(row=4, column=2, pady=20)

# Configure grid weights to make the layout more flexible
root.grid_columnconfigure(0, weight=1)  # Label column
root.grid_columnconfigure(1, weight=1)  # Left input column
root.grid_columnconfigure(2, weight=1)  # Right output column

# Start the Tkinter event loop
root.mainloop()