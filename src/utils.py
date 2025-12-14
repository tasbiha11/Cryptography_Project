def bytes_to_matrix(text):
    """Convert 16-byte array into 4x4 matrix (state).
    AES processes data in a 4x4 matrix (state).
    Bytes are filled column by column (not row by row).
    
    Args:
        text: bytes or list of 16 bytes
        
    Returns:
        4x4 matrix (list of lists)"""
    if len(text) != 16:
        raise ValueError(f"Input must be 16 bytes, got {len(text)} bytes")
    
    #creates 4x4 matrix filled with zeros
    matrix = [[0] * 4 for _ in range(4)]
    
    #fills column by column
    for i in range(4):
        for j in range(4):
            matrix[j][i] = text[i * 4 + j]
    
    return matrix


def matrix_to_bytes(matrix):
    """Convert 4x4 matrix back to 16-byte array.
    Args:
        matrix: 4x4 matrix (list of lists)    
    Returns:
        bytes: 16-byte array"""
    if len(matrix) != 4 or any(len(row) != 4 for row in matrix):
        raise ValueError("Input must be a 4x4 matrix")
    
    result = bytearray(16)
    
    #extracts column by column
    for i in range(4):
        for j in range(4):
            result[i * 4 + j] = matrix[j][i]
    
    return bytes(result)

def xor_bytes(a, b):
    """XOR two byte arrays of equal length.
    Args:
        a, b: bytes or bytearrays of same length   
    Returns:
        bytes: XOR result"""
    if len(a) != len(b):
        raise ValueError(f"Byte arrays must be same length: {len(a)} != {len(b)}")
    
    return bytes(x ^ y for x, y in zip(a, b))

def sub_bytes_byte(byte, s_box):
    """Substitute a single byte using S-box. 
    Args:
        byte: integer (0-255)
        s_box: S-box lookup table     
    Returns:
        int: substituted byte"""
    return s_box[byte]

def shift_row(row, n):
    """Shift a row left by n positions (circular shift).
    Args:
        row: list of 4 bytes
        n: number of positions to shift     
    Returns:
        list: shifted row"""
    return row[n:] + row[:n]

def inv_shift_row(row, n):
    """Shift a row right by n positions (circular shift).
    Args:
        row: list of 4 bytes
        n: number of positions to shift    
    Returns:
        list: shifted row"""
    return row[-n:] + row[:-n]

def galois_mult(a, b):
    """Multiply two numbers in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1.
    Args:
        a, b: integers (0-255)    
    Returns:
        int: product in GF(2^8)"""
    p = 0
    for _ in range(8):
        if b & 1:  #if LSB of b is set
            p ^= a
        hi_bit_set = a & 0x80  #check if high bit of a is set
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b  #x^8 + x^4 + x^3 + x + 1 (0x11b), but we only need modulo
        b >>= 1
    return p & 0xFF  #ensures result is within byte range


def pad_pkcs7(data, block_size=16):
    """Pad data using PKCS#7 padding.
    Args:
        data: bytes to pad
        block_size: block size in bytes (default 16 for AES)  
    Returns:
        bytes: padded data"""
    
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad_pkcs7(data, block_size=16):
    """Remove PKCS#7 padding.
    Args:
        data: padded bytes
        block_size: block size in bytes    
    Returns:
        bytes: unpadded data    
    Raises:
        ValueError: if padding is invalid"""
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Data length must be multiple of block size")
    
    padding_length = data[-1]
    
    #validates padding
    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Invalid padding length")
    
    #check all padding bytes are correct
    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding bytes")
    
    return data[:-padding_length]

def bytes_to_hex_string(data, separator=" "):
    """
    Convert bytes to hex string for display.
    
    Args:
        data: bytes to convert
        separator: string to separate hex bytes
        
    Returns:
        str: hex string
    """
    return separator.join(f"{b:02x}" for b in data)

def hex_string_to_bytes(hex_str):
    """
    Convert hex string to bytes.
    Args:
        hex_str: hex string (with or without spaces)      
    Returns:
        bytes: converted bytes
    """
    hex_str = hex_str.replace(" ", "").replace("\n", "")
    if len(hex_str) % 2 != 0:
        raise ValueError("Hex string must have even number of characters")
    return bytes.fromhex(hex_str)

def print_state(state, title="State"):
    """Pretty print a 4x4 state matrix.
    Args:
        state: 4x4 matrix
        title: title to display
    """
    print(f"\n{title}:")
    for i in range(4):
        print("  " + " ".join(f"{state[i][j]:02x}" for j in range(4)))