#!/usr/bin/env python3
"""
AES Implementation Demo
Demonstrates the AES implementation with interactive examples
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from aes import AES
import utils


def print_banner():
    """Print program banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════╗
    ║        AES Implementation from Scratch                ║
    ║        Advanced Encryption Standard (AES-128)         ║
    ╚═══════════════════════════════════════════════════════╝
    """
    print(banner)


def demo_single_block():
    """Demonstrate single block encryption/decryption"""
    print("\n" + "═" * 60)
    print("DEMO 1: Single Block Encryption/Decryption")
    print("═" * 60)
    
    # Use the FIPS-197 test vector
    key = bytes([
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    ])
    
    plaintext = bytes([
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    ])
    
    print(f"Key:        {utils.bytes_to_hex_string(key)}")
    print(f"Plaintext:  {utils.bytes_to_hex_string(plaintext)}")
    
    # Create AES instance with verbose output to see steps
    print("\nCreating AES instance with verbose output...")
    cipher = AES(key, verbose=True)
    
    # Encrypt
    print("\n" + "-" * 40)
    print("ENCRYPTION PROCESS")
    print("-" * 40)
    ciphertext = cipher.encrypt_block(plaintext)
    print(f"\nFinal Ciphertext: {utils.bytes_to_hex_string(ciphertext)}")
    
    # Expected ciphertext from FIPS-197
    expected = bytes([
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    ])
    
    if ciphertext == expected:
        print("✅ Encryption matches FIPS-197 test vector!")
    else:
        print("❌ Encryption doesn't match expected output")
    
    # Decrypt (turn off verbose for cleaner output)
    cipher.verbose = False
    print("\n" + "-" * 40)
    print("DECRYPTION PROCESS")
    print("-" * 40)
    decrypted = cipher.decrypt_block(ciphertext)
    print(f"\nDecrypted: {utils.bytes_to_hex_string(decrypted)}")
    
    if decrypted == plaintext:
        print("✅ Decryption successful!")
    else:
        print("❌ Decryption failed!")


def demo_text_encryption():
    """Demonstrate text encryption/decryption"""
    print("\n" + "═" * 60)
    print("DEMO 2: Text Message Encryption/Decryption")
    print("═" * 60)
    
    # Simple key and message
    key = b"MySecretKey12345"  # 16 bytes
    message = b"Hello, this is a secret message for AES demonstration!"
    
    print(f"Key:        {key.decode()}")
    print(f"Message:    {message.decode()}")
    print(f"Message (hex): {utils.bytes_to_hex_string(message[:32])}...")
    
    # Create AES instance
    cipher = AES(key, verbose=False)
    
    # Encrypt
    print("\nEncrypting message...")
    ciphertext = cipher.encrypt(message)
    print(f"Ciphertext (hex): {utils.bytes_to_hex_string(ciphertext[:32])}...")
    print(f"Total ciphertext length: {len(ciphertext)} bytes")
    
    # Decrypt
    print("\nDecrypting ciphertext...")
    decrypted = cipher.decrypt(ciphertext)
    print(f"Decrypted: {decrypted.decode()}")
    
    if decrypted == message:
        print("✅ Text encryption/decryption successful!")
    else:
        print("❌ Text encryption/decryption failed!")


def demo_interactive():
    """Interactive demo where user can enter their own data"""
    print("\n" + "═" * 60)
    print("DEMO 3: Interactive Encryption/Decryption")
    print("═" * 60)
    
    print("\nEnter your own data to encrypt (or press Enter for default):")
    
    # Get key
    key_input = input("Enter 16-byte key (as text, will be padded/trimmed): ").strip()
    if not key_input:
        key = b"SixteenByteKey!!"
    else:
        # Ensure key is 16 bytes
        key = key_input.encode()
        if len(key) < 16:
            key = key.ljust(16, b' ')
        elif len(key) > 16:
            key = key[:16]
    
    # Get message
    message_input = input("Enter message to encrypt: ").strip()
    if not message_input:
        message_input = "This is a test message for AES encryption!"
    
    message = message_input.encode()
    
    print(f"\nUsing key: {key}")
    print(f"Message: {message_input}")
    
    # Create AES instance
    cipher = AES(key, verbose=False)
    
    # Show verbose for first block if message is long enough
    if len(message) >= 16:
        print("\nFirst block encryption details:")
        cipher.verbose = True
        first_block = message[:16]
        first_ciphertext = cipher.encrypt_block(first_block)
        cipher.verbose = False
    
    # Encrypt entire message
    print("\nEncrypting entire message...")
    ciphertext = cipher.encrypt(message)
    
    print(f"\nCiphertext (hex):")
    hex_str = utils.bytes_to_hex_string(ciphertext)
    # Print in groups of 32 hex chars (16 bytes)
    for i in range(0, len(hex_str), 32):
        print(f"  {hex_str[i:i+32]}")
    
    # Decrypt
    print("\nDecrypting...")
    decrypted = cipher.decrypt(ciphertext)
    
    print(f"\nDecrypted message: {decrypted.decode()}")
    
    if decrypted == message:
        print("\n✅ Your message was successfully encrypted and decrypted!")
    else:
        print("\n❌ Something went wrong!")


def demo_educational():
    """Educational demo showing AES internals"""
    print("\n" + "═" * 60)
    print("DEMO 4: Educational - Show AES Internals")
    print("═" * 60)
    
    print("\nThis demo shows the internal state transformations in AES.")
    print("We'll use a simple input to see each step.")
    
    # Simple input for clarity
    key = bytes([0] * 16)  # All zeros
    plaintext = bytes([i for i in range(16)])  # 0x00 to 0x0f
    
    print(f"\nKey (all zeros): {utils.bytes_to_hex_string(key)}")
    print(f"Plaintext: {utils.bytes_to_hex_string(plaintext)}")
    
    print("\nCreating AES with verbose output to see each step...")
    cipher = AES(key, verbose=True)
    
    # Convert to state matrix to show initial state
    state = utils.bytes_to_matrix(plaintext)
    print("\nInitial State Matrix:")
    print("(Bytes are arranged column-wise in AES)")
    utils.print_state(state)
    
    # Show what the state looks like
    print("\nState representation:")
    print("Each column is processed together in AES operations")
    
    # Encrypt with full verbose output
    print("\n" + "=" * 50)
    print("Starting encryption process...")
    print("=" * 50)
    ciphertext = cipher.encrypt_block(plaintext)
    
    print(f"\nFinal ciphertext: {utils.bytes_to_hex_string(ciphertext)}")
    
    # Show the decryption process too
    print("\n" + "=" * 50)
    print("Starting decryption process...")
    print("=" * 50)
    decrypted = cipher.decrypt_block(ciphertext)
    
    print(f"\nDecrypted: {utils.bytes_to_hex_string(decrypted)}")
    
    if decrypted == plaintext:
        print("\n✅ AES round-trip successful!")
    else:
        print("\n❌ Round-trip failed!")


def main():
    """Main demo function"""
    print_banner()
    
    demos = {
        '1': ("Single Block (FIPS-197 Test Vector)", demo_single_block),
        '2': ("Text Message Encryption", demo_text_encryption),
        '3': ("Interactive Encryption", demo_interactive),
        '4': ("Educational (Show Internals)", demo_educational),
        'q': ("Quit", None)
    }
    
    while True:
        print("\n" + "═" * 60)
        print("SELECT A DEMO")
        print("═" * 60)
        
        for key, (description, _) in demos.items():
            print(f"  {key}. {description}")
        
        choice = input("\nEnter your choice (1-4, q to quit): ").strip().lower()
        
        if choice == 'q':
            print("\nThank you for exploring AES implementation!")
            break
        
        if choice in demos and demos[choice][1]:
            try:
                demos[choice][1]()
            except Exception as e:
                print(f"\n❌ Error during demo: {e}")
                print("Please try again with valid inputs.")
        else:
            print("\n❌ Invalid choice. Please try again.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted. Goodbye!")
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        print("Please make sure all required files are in place.")