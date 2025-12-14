#!/usr/bin/env python3
"""
Quick start script for AES implementation demo
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def main():
    print("AES Implementation from Scratch - Quick Demo")
    print("=" * 50)
    
    # Check if all files exist
    required_files = [
        'src/constants.py',
        'src/utils.py', 
        'src/aes.py',
        'src/test_aes.py',
        'examples/demo.py'
    ]
    
    print("\nChecking required files...")
    for file in required_files:
        if os.path.exists(file):
            print(f"✅ {file}")
        else:
            print(f"❌ {file} - NOT FOUND")
            print("\nPlease make sure all files are in place.")
            return
    
    print("\nAll files found! Running quick test...")
    print("-" * 50)
    
    # Run a simple test
    try:
        from src import aes, utils
        
        # Quick test
        key = b"Sixteen byte key"
        plaintext = b"Hello AES!"
        
        cipher = aes.AES(key, verbose=False)
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)
        
        print(f"Key:        {key}")
        print(f"Plaintext:  {plaintext}")
        print(f"Ciphertext: {utils.bytes_to_hex_string(ciphertext)}")
        print(f"Decrypted:  {decrypted}")
        
        if decrypted == plaintext:
            print("\n✅ Quick test passed!")
        else:
            print("\n❌ Quick test failed!")
            
    except Exception as e:
        print(f"\n❌ Error during quick test: {e}")
        return
    
    print("\n" + "=" * 50)
    print("What would you like to do next?")
    print("1. Run comprehensive test suite")
    print("2. Run interactive demo")
    print("3. Exit")
    
    choice = input("\nEnter choice (1-3): ").strip()
    
    if choice == '1':
        print("\nRunning test suite...")
        print("-" * 50)
        exec(open('src/test_aes.py').read())
    elif choice == '2':
        print("\nStarting interactive demo...")
        print("-" * 50)
        exec(open('examples/demo.py').read())
    else:
        print("\nGoodbye!")

if __name__ == "__main__":
    main()