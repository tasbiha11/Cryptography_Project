# AES Implementation from Scratch

A pure Python implementation of the Advanced Encryption Standard (AES) from scratch, designed for Cryptography and Computer Security course project in 2022. Implements AES-128 with support for ECB mode.

##  Overview

This project implements AES (Rijndael algorithm) following the FIPS-197 specification. It's designed to be educational, showing each step of the encryption/decryption process with clear, documented code.

**Features:**
- ✅ AES-128 (16-byte key, 10 rounds)
- ✅ Full encryption and decryption
- ✅ ECB mode with PKCS#7 padding
- ✅ Support for multiple block encryption
- ✅ Comprehensive test suite with known test vectors
- ✅ Interactive demos showing internal steps
- ✅ Clean, well-documented code
- ✅ No external dependencies

### Installation

No installation required! Just clone and run:

```bash
# Clone the repository
git clone https://github.com/yourusername/aes-from-scratch.git
cd aes-from-scratch

# Run tests to verify implementation
python -m src.test_aes

# Run interactive demo
python examples/demo.py
from src.aes import AES
import src.utils as utils

# Create AES instance with a 16-byte key
key = b"Sixteen byte key"
cipher = AES(key, verbose=True)  # Set verbose=True to see steps

# Encrypt a message
plaintext = b"Hello AES World!"
ciphertext = cipher.encrypt(plaintext)
print(f"Ciphertext: {utils.bytes_to_hex_string(ciphertext)}")

# Decrypt the message
decrypted = cipher.decrypt(ciphertext)
print(f"Decrypted: {decrypted}")

# Run all tests
python -m unittest src.test_aes

# Run with verbose output
python -m src.test_aes
python -m src.test_aes
