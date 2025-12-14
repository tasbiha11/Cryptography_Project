"""
Test suite for AES implementation
Tests against known test vectors from FIPS-197 and NIST
"""

import unittest
from . import aes
from . import utils


class TestAES(unittest.TestCase):
    """Test cases for AES implementation"""
    
    def setUp(self):
        """Set up test fixtures"""
        #known test vectors from FIPS-197 Appendix A
        self.test_key = bytes([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ])
        
        self.test_plaintext = bytes([
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
        ])
        
        self.expected_ciphertext = bytes([
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
        ])
        
        #additional test vector from NIST
        self.nist_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        self.nist_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.nist_ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    
    def test_bytes_to_matrix(self):
        """Test bytes to matrix conversion"""
        data = bytes(range(16))  # 0x00 to 0x0f
        matrix = utils.bytes_to_matrix(data)
        
        #expected matrix (filled column-wise)
        #column 0: 0x00, 0x01, 0x02, 0x03
        #column 1: 0x04, 0x05, 0x06, 0x07
        #etc.
        expected = [
            [0x00, 0x04, 0x08, 0x0c],
            [0x01, 0x05, 0x09, 0x0d],
            [0x02, 0x06, 0x0a, 0x0e],
            [0x03, 0x07, 0x0b, 0x0f]
        ]
        
        self.assertEqual(matrix, expected)
        
        #test round trip
        back_to_bytes = utils.matrix_to_bytes(matrix)
        self.assertEqual(data, back_to_bytes)
    
    def test_xor_bytes(self):
        """Test XOR operation on bytes"""
        a = bytes([0x00, 0xff, 0x55, 0xaa])
        b = bytes([0xff, 0x00, 0xaa, 0x55])
        expected = bytes([0xff, 0xff, 0xff, 0xff])
        
        result = utils.xor_bytes(a, b)
        self.assertEqual(result, expected)
    
    def test_galois_mult(self):
        """Test Galois Field multiplication"""
        #test cases from AES specification
        self.assertEqual(utils.galois_mult(0x57, 0x83), 0xc1)
        self.assertEqual(utils.galois_mult(0x57, 0x13), 0xfe)
        
        #test identity
        self.assertEqual(utils.galois_mult(0xff, 0x01), 0xff)
        self.assertEqual(utils.galois_mult(0x00, 0xff), 0x00)
    
    def test_padding(self):
        """Test PKCS#7 padding"""
        #test exact block size
        data = b"A" * 16
        padded = utils.pad_pkcs7(data)
        self.assertEqual(len(padded), 32)  # Should add full block of padding
        self.assertEqual(padded[-1], 16)   # Padding value should be 16
        
        #test short data
        data = b"Hello"
        padded = utils.pad_pkcs7(data)
        self.assertEqual(len(padded), 16)  # Should pad to block size
        self.assertEqual(padded[-1], 11)   # 16 - 5 = 11
        
        #test round trip
        unpadded = utils.unpad_pkcs7(padded)
        self.assertEqual(unpadded, data)
    
    def test_key_expansion(self):
        """Test key expansion against known values"""
        #test vector from FIPS-197 Appendix A
        cipher = aes.AES(self.test_key, verbose=False)
        
        #check number of round keys
        self.assertEqual(len(cipher.round_keys), cipher.n_rounds + 1)
        
        #check first round key (should be the original key)
        round_key_0 = utils.matrix_to_bytes(cipher.round_keys[0])
        self.assertEqual(round_key_0, self.test_key)
        
        #check a known expanded key (round 1 from FIPS-197)
        #we'll just verify the structure is correct
        for i, key in enumerate(cipher.round_keys):
            self.assertEqual(len(key), 4)
            for row in key:
                self.assertEqual(len(row), 4)
    
    def test_encrypt_block_fips197(self):
        """Test encryption with FIPS-197 test vector"""
        cipher = aes.AES(self.test_key, verbose=False)
        
        #encrypt single block
        ciphertext = cipher.encrypt_block(self.test_plaintext)
        
        #compare with expected ciphertext
        self.assertEqual(ciphertext, self.expected_ciphertext)
        
        print("\n✓ FIPS-197 Test Vector Passed")
        print(f"Plaintext:  {utils.bytes_to_hex_string(self.test_plaintext)}")
        print(f"Ciphertext: {utils.bytes_to_hex_string(ciphertext)}")
        print(f"Expected:   {utils.bytes_to_hex_string(self.expected_ciphertext)}")
    
    def test_decrypt_block_fips197(self):
        """Test decryption with FIPS-197 test vector"""
        cipher = aes.AES(self.test_key, verbose=False)
        
        #decrypt the ciphertext
        plaintext = cipher.decrypt_block(self.expected_ciphertext)
        
        #should get back the original plaintext
        self.assertEqual(plaintext, self.test_plaintext)
        
        print("\n✓ FIPS-197 Decryption Test Passed")
        print(f"Ciphertext: {utils.bytes_to_hex_string(self.expected_ciphertext)}")
        print(f"Plaintext:  {utils.bytes_to_hex_string(plaintext)}")
        print(f"Expected:   {utils.bytes_to_hex_string(self.test_plaintext)}")
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption followed by decryption"""
        cipher = aes.AES(self.test_key, verbose=False)
        
        #test with random data
        import random
        random_data = bytes(random.getrandbits(8) for _ in range(16))
        
        ciphertext = cipher.encrypt_block(random_data)
        plaintext = cipher.decrypt_block(ciphertext)
        
        self.assertEqual(plaintext, random_data)
        
        print(f"\n✓ Round-trip test passed for random data")
    
    def test_nist_test_vector(self):
        """Test with NIST test vector"""
        cipher = aes.AES(self.nist_key, verbose=False)
        
        #encrypt
        ciphertext = cipher.encrypt_block(self.nist_plaintext)
        self.assertEqual(ciphertext, self.nist_ciphertext)
        
        #decrypt
        plaintext = cipher.decrypt_block(self.nist_ciphertext)
        self.assertEqual(plaintext, self.nist_plaintext)
        
        print("\n✓ NIST Test Vector Passed")
        print(f"Key:        {utils.bytes_to_hex_string(self.nist_key)}")
        print(f"Plaintext:  {utils.bytes_to_hex_string(self.nist_plaintext)}")
        print(f"Ciphertext: {utils.bytes_to_hex_string(ciphertext)}")
    
    def test_multi_block_encryption(self):
        """Test encryption/decryption of multiple blocks"""
        cipher = aes.AES(self.test_key, verbose=False)
        
        #create data longer than one block
        data = b"This is a test message that is longer than 16 bytes!"
        
        #encrypt
        ciphertext = cipher.encrypt(data)
        
        #should be multiple of 16 bytes
        self.assertEqual(len(ciphertext) % 16, 0)
        
        #decrypt
        plaintext = cipher.decrypt(ciphertext)
        
        #should get original data back
        self.assertEqual(plaintext, data)
        
        print(f"\n✓ Multi-block encryption/decryption test passed")
        print(f"Original length: {len(data)} bytes")
        print(f"Encrypted length: {len(ciphertext)} bytes")
    
    def test_different_key_sizes(self):
        """Test AES with different key sizes"""
        #AES-128 (already tested)
        key_128 = bytes(range(16))
        cipher_128 = aes.AES(key_128, verbose=False)
        self.assertEqual(cipher_128.n_rounds, 10)
        
        #AES-192
        key_192 = bytes(range(24))
        cipher_192 = aes.AES(key_192, verbose=False)
        self.assertEqual(cipher_192.n_rounds, 12)
        
        #AES-256
        key_256 = bytes(range(32))
        cipher_256 = aes.AES(key_256, verbose=False)
        self.assertEqual(cipher_256.n_rounds, 14)
        
        print("\n✓ Different key sizes supported:")
        print(f"  AES-128: {len(key_128)} bytes -> {cipher_128.n_rounds} rounds")
        print(f"  AES-192: {len(key_192)} bytes -> {cipher_192.n_rounds} rounds")
        print(f"  AES-256: {len(key_256)} bytes -> {cipher_256.n_rounds} rounds")
    
    def test_error_handling(self):
        """Test error conditions"""
        #Invalid key size
        with self.assertRaises(ValueError):
            aes.AES(b"short_key")
        
        #Invalid block size for encrypt_block
        cipher = aes.AES(self.test_key, verbose=False)
        with self.assertRaises(ValueError):
            cipher.encrypt_block(b"short")
        
        #Invalid block size for decrypt_block
        with self.assertRaises(ValueError):
            cipher.decrypt_block(b"short")
        
        #Invalid ciphertext length for multi-block decrypt
        with self.assertRaises(ValueError):
            cipher.decrypt(b"not_multiple_of_16")
        
        print("\n✓ Error handling tests passed")


def run_comprehensive_test():
    """Run comprehensive test suite with verbose output"""
    print("=" * 60)
    print("AES IMPLEMENTATION COMPREHENSIVE TEST SUITE")
    print("=" * 60)
    
    #Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAES)
    
    #Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n🎉 All tests passed! AES implementation is working correctly.")
    else:
        print("\n❌ Some tests failed. Check implementation.")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    #Run the comprehensive test suite
    success = run_comprehensive_test()
    
    #Also run a simple demo if tests pass
    if success:
        print("\n" + "=" * 60)
        print("QUICK DEMO")
        print("=" * 60)
        
        #Simple demonstration
        key = b"Sixteen byte key"
        plaintext = b"Hello AES World!"
        
        print(f"Key:        {utils.bytes_to_hex_string(key)}")
        print(f"Plaintext:  {plaintext}")
        
        #Create AES instance with verbose output
        cipher = aes.AES(key, verbose=False)
        
        #Encrypt
        ciphertext = cipher.encrypt(plaintext)
        print(f"Ciphertext: {utils.bytes_to_hex_string(ciphertext)}")
        
        #Decrypt
        decrypted = cipher.decrypt(ciphertext)
        print(f"Decrypted:  {decrypted}")
        
        if decrypted == plaintext:
            print("\n✅ Encryption/Decryption successful!")
        else:
            print("\n❌ Something went wrong!")