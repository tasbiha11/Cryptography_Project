from . import constants
from . import utils


class AES:
    """AES implementation supporting encryption and decryption"""
    
    def __init__(self, key, verbose=False):
        """
        Initialize AES with a key.
        
        Args:
            key: bytes, must be 16 bytes for AES-128
            verbose: bool, if True prints intermediate states
        """
        if len(key) not in constants.ROUNDS:
            raise ValueError(f"Key must be 16, 24, or 32 bytes, got {len(key)}")
        
        self.key = key
        self.key_size = len(key)
        self.n_rounds = constants.ROUNDS[self.key_size]
        self.verbose = verbose
        
        #expand the key for all rounds
        self.round_keys = self._key_expansion(key)
        
        if verbose:
            print(f"AES initialized with {self.key_size*8}-bit key")
            print(f"Key: {utils.bytes_to_hex_string(key)}")
            print(f"Number of rounds: {self.n_rounds}")
    
    def _key_expansion(self, key):
        """
        Key Expansion: Generate round keys from the initial key.
        
        Args:
            key: initial key bytes
            
        Returns:
            list: expanded round keys (each as 4x4 matrix)
        """
        #initialize round keys
        round_keys = []
        
        #first round key is the original key
        key_matrix = utils.bytes_to_matrix(key)
        round_keys.append(key_matrix)
        
        #generate remaining round keys
        for i in range(1, self.n_rounds + 1):
            prev_key = round_keys[-1]
            new_key = [[0] * 4 for _ in range(4)]
            
            #first column of new key
            temp = [prev_key[j][3] for j in range(4)]  # Last column of previous key
            
            #rotWord: rotate temp left by 1
            temp = temp[1:] + temp[:1]
            
            #subWord: substitute bytes using S-box
            temp = [constants.S_BOX[b] for b in temp]
            
            #XOR with Rcon
            temp[0] ^= constants.RCON[i-1]
            
            #XOR with first column of previous key
            for j in range(4):
                new_key[j][0] = prev_key[j][0] ^ temp[j]
            
            #remaining columns
            for col in range(1, 4):
                for row in range(4):
                    new_key[row][col] = new_key[row][col-1] ^ prev_key[row][col]
            
            round_keys.append(new_key)
            
            if self.verbose and i <= 3:  # Show first few round keys
                print(f"Round key {i}: {utils.bytes_to_hex_string(utils.matrix_to_bytes(new_key))}")
        
        return round_keys
    
    def _sub_bytes(self, state, s_box):
        """Substitute each byte in state using S-box"""
        for i in range(4):
            for j in range(4):
                state[i][j] = s_box[state[i][j]]
        return state
    
    def _shift_rows(self, state):
        """Shift rows of state matrix"""
        #Row 0: no shift
        #Row 1: shift left by 1
        state[1] = utils.shift_row(state[1], 1)
        #Row 2: shift left by 2
        state[2] = utils.shift_row(state[2], 2)
        #Row 3: shift left by 3
        state[3] = utils.shift_row(state[3], 3)
        return state
    
    def _inv_shift_rows(self, state):
        """Inverse shift rows of state matrix"""
        #Row 0: no shift
        #Row 1: shift right by 1
        state[1] = utils.inv_shift_row(state[1], 1)
        #Row 2: shift right by 2
        state[2] = utils.inv_shift_row(state[2], 2)
        #Row 3: shift right by 3
        state[3] = utils.inv_shift_row(state[3], 3)
        return state
    
    def _mix_columns(self, state, mix_matrix):
        """MixColumns transformation"""
        new_state = [[0] * 4 for _ in range(4)]
        
        for col in range(4):
            for row in range(4):
                # Dot product of mix_matrix row and state column in GF(2^8)
                value = 0
                for k in range(4):
                    value ^= utils.galois_mult(mix_matrix[row][k], state[k][col])
                new_state[row][col] = value
        
        return new_state
    
    def _add_round_key(self, state, round_key):
        """XOR state with round key"""
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
        return state
    
    def _print_round_state(self, round_num, state, operation):
        """Print state for debugging if verbose is True"""
        if self.verbose:
            print(f"\n{operation} Round {round_num}:")
            utils.print_state(state)
    
    def encrypt_block(self, plaintext):
        """
        Encrypt a single 16-byte block.
        
        Args:
            plaintext: 16 bytes to encrypt
            
        Returns:
            bytes: 16 encrypted bytes
        """
        if len(plaintext) != 16:
            raise ValueError(f"Block must be 16 bytes, got {len(plaintext)}")
        
        if self.verbose:
            print("\n" + "="*50)
            print("ENCRYPTION START")
            print(f"Plaintext: {utils.bytes_to_hex_string(plaintext)}")
        
        #convert plaintext to state matrix
        state = utils.bytes_to_matrix(plaintext)
        
        if self.verbose:
            utils.print_state(state, "Initial State")
            utils.print_state(self.round_keys[0], "Round Key 0")
        
        #initial round: AddRoundKey only
        state = self._add_round_key(state, self.round_keys[0])
        self._print_round_state(0, state, "After AddRoundKey")
        
        #main rounds (1 to n_rounds-1)
        for round_num in range(1, self.n_rounds):
            #subBytes
            state = self._sub_bytes(state, constants.S_BOX)
            self._print_round_state(round_num, state, "After SubBytes")
            
            #shiftRows
            state = self._shift_rows(state)
            self._print_round_state(round_num, state, "After ShiftRows")
            
            #mixColumns
            state = self._mix_columns(state, constants.MIX_COLUMNS_MATRIX)
            self._print_round_state(round_num, state, "After MixColumns")
            
            #addRoundKey
            state = self._add_round_key(state, self.round_keys[round_num])
            self._print_round_state(round_num, state, "After AddRoundKey")
        
        #final round (no MixColumns)
        #subBytes
        state = self._sub_bytes(state, constants.S_BOX)
        self._print_round_state(self.n_rounds, state, "After SubBytes")
        
        #shiftRows
        state = self._shift_rows(state)
        self._print_round_state(self.n_rounds, state, "After ShiftRows")
        
        #addRoundKey
        state = self._add_round_key(state, self.round_keys[self.n_rounds])
        self._print_round_state(self.n_rounds, state, "After AddRoundKey")
        
        #convert state back to bytes
        ciphertext = utils.matrix_to_bytes(state)
        
        if self.verbose:
            print(f"\nCiphertext: {utils.bytes_to_hex_string(ciphertext)}")
            print("ENCRYPTION COMPLETE")
            print("="*50)
        
        return ciphertext
    
    def decrypt_block(self, ciphertext):
        """
        Decrypt a single 16-byte block.
        
        Args:
            ciphertext: 16 bytes to decrypt
            
        Returns:
            bytes: 16 decrypted bytes
        """
        if len(ciphertext) != 16:
            raise ValueError(f"Block must be 16 bytes, got {len(ciphertext)}")
        
        if self.verbose:
            print("\n" + "="*50)
            print("DECRYPTION START")
            print(f"Ciphertext: {utils.bytes_to_hex_string(ciphertext)}")
        
        #convert ciphertext to state matrix
        state = utils.bytes_to_matrix(ciphertext)
        
        if self.verbose:
            utils.print_state(state, "Initial State")
            utils.print_state(self.round_keys[self.n_rounds], "Round Key 10")
        
        #initial round (reverse of final encryption round)
        state = self._add_round_key(state, self.round_keys[self.n_rounds])
        self._print_round_state(self.n_rounds, state, "After AddRoundKey")
        
        state = self._inv_shift_rows(state)
        self._print_round_state(self.n_rounds, state, "After InvShiftRows")
        
        state = self._sub_bytes(state, constants.INV_S_BOX)
        self._print_round_state(self.n_rounds, state, "After InvSubBytes")
        
        #main rounds (n_rounds-1 to 1)
        for round_num in range(self.n_rounds - 1, 0, -1):
            #addRoundKey
            state = self._add_round_key(state, self.round_keys[round_num])
            self._print_round_state(round_num, state, "After AddRoundKey")
            
            #invMixColumns
            state = self._mix_columns(state, constants.INV_MIX_COLUMNS_MATRIX)
            self._print_round_state(round_num, state, "After InvMixColumns")
            
            #invShiftRows
            state = self._inv_shift_rows(state)
            self._print_round_state(round_num, state, "After InvShiftRows")
            
            #invSubBytes
            state = self._sub_bytes(state, constants.INV_S_BOX)
            self._print_round_state(round_num, state, "After InvSubBytes")
        
        #final round
        state = self._add_round_key(state, self.round_keys[0])
        self._print_round_state(0, state, "After AddRoundKey")
        
        #convert state back to bytes
        plaintext = utils.matrix_to_bytes(state)
        
        if self.verbose:
            print(f"\nPlaintext: {utils.bytes_to_hex_string(plaintext)}")
            print("DECRYPTION COMPLETE")
            print("="*50)
        
        return plaintext
    
    def encrypt(self, plaintext, mode='ecb'):
        """
        Encrypt arbitrary-length plaintext.
        
        Args:
            plaintext: bytes to encrypt
            mode: encryption mode ('ecb' only for now)
            
        Returns:
            bytes: encrypted ciphertext
        """
        if mode.lower() != 'ecb':
            raise ValueError(f"Mode {mode} not supported yet. Only ECB is implemented.")
        
        #pad the plaintext
        padded = utils.pad_pkcs7(plaintext)
        
        #encrypt block by block
        ciphertext = bytearray()
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            encrypted_block = self.encrypt_block(block)
            ciphertext.extend(encrypted_block)
        
        return bytes(ciphertext)
    
    def decrypt(self, ciphertext, mode='ecb'):
        """
        Decrypt ciphertext.
        
        Args:
            ciphertext: bytes to decrypt (must be multiple of 16)
            mode: decryption mode ('ecb' only for now)
            
        Returns:
            bytes: decrypted plaintext (with padding removed)
        """
        if mode.lower() != 'ecb':
            raise ValueError(f"Mode {mode} not supported yet. Only ECB is implemented.")
        
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")
        
        #decrypt block by block
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = self.decrypt_block(block)
            plaintext.extend(decrypted_block)
        
        #remove padding
        return utils.unpad_pkcs7(bytes(plaintext))