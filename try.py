class ColumnarTranspositionCipher:
    def __init__(self, key):
        self.key = key
    
    def encrypt(self, plain_text):
        plain_text = plain_text.replace(" ", "").upper()
        num_columns = len(self.key)
        num_rows = (len(plain_text) + num_columns - 1) // num_columns
        padded_plain_text = plain_text.ljust(num_rows * num_columns, 'X')
        
        grid = [[''] * num_columns for _ in range(num_rows)]
        for i, char in enumerate(padded_plain_text):
            row = i // num_columns
            col = i % num_columns
            grid[row][col] = char
        
        encrypted_text = ''
        for index in self.key:
            encrypted_text += ''.join(row[index] for row in grid)
        
        return encrypted_text

    def decrypt(self, cipher_text):
        num_columns = len(self.key)
        num_rows = len(cipher_text) // num_columns
        
        grid = [[''] * num_columns for _ in range(num_rows)]
        
        column_lengths = [num_rows] * num_columns
        remainder = len(cipher_text) % num_columns
        for i in range(remainder):
            column_lengths[self.key[i]] += 1
        
        index = 0
        for col in self.key:
            for row in range(column_lengths[col]):
                grid[row][col] = cipher_text[index]
                index += 1
        
        decrypted_text = ''.join(''.join(row) for row in grid)
        
        return decrypted_text.rstrip('X')


class SubstitutionCipher:
    def __init__(self, key):
        self.key = key
    
    def encrypt(self, plain_text):
        encrypted_text = ""
        for char in plain_text:
            if char.isalpha():
                if char.islower():
                    encrypted_char = self.key[ord(char) - ord('a')]
                else:
                    encrypted_char = self.key[ord(char) - ord('A')].upper()
                encrypted_text += encrypted_char
            else:
                encrypted_text += char
        return encrypted_text

    def decrypt(self, cipher_text):
        decrypted_text = ""
        for char in cipher_text:
            if char.isalpha():
                if char.islower():
                    decrypted_char = chr(self.key.lower().index(char) + ord('a'))
                else:
                    decrypted_char = chr(self.key.index(char.lower()) + ord('A'))
                decrypted_text += decrypted_char
            else:
                decrypted_text += char
        return decrypted_text


class RailFenceCipher:
    def __init__(self, rails):
        self.rails = rails
    
    def encrypt(self, plain_text):
        rail = [''] * self.rails
        direction = -1
        row = 0
        
        for char in plain_text:
            rail[row] += char
            if row == 0 or row == self.rails - 1:
                direction *= -1
            row += direction
        
        cipher_text = ''.join(rail)
        return cipher_text

    def decrypt(self, cipher_text):
        cycle = 2 * self.rails - 2
        message_length = len(cipher_text)
        decrypted = [''] * message_length
        
        for row in range(self.rails):
            step = 2 * row
            j = 0
            for i in range(row, message_length, cycle):
                decrypted[i] = cipher_text[j]
                j += 1
                if step != cycle and step != 0 and i + cycle - step < message_length:
                    decrypted[i + cycle - step] = cipher_text[j]
                    j += 1
                step += 2
        
        return ''.join(decrypted)


class Rot13Cipher:
    def encrypt(self, plain_text):
        encrypted_text = ""
        for char in plain_text:
            if char.isalpha():
                shift = 13
                if char.islower():
                    start = ord('a')
                else:
                    start = ord('A')
                encrypted_char = chr((ord(char) - start + shift) % 26 + start)
                encrypted_text += encrypted_char
            else:
                encrypted_text += char
        return encrypted_text

    def decrypt(self, cipher_text):
        decrypted_text = ""
        for char in cipher_text:
            if char.isalpha():
                shift = 13
                if char.islower():
                    start = ord('a')
                else:
                    start = ord('A')
                decrypted_char = chr((ord(char) - start - shift) % 26 + start)
                decrypted_text += decrypted_char
            else:
                decrypted_text += char
        return decrypted_text


class AffineCipher:
    def __init__(self, a, b):
        self.a = a
        self.b = b
    
    def encrypt(self, plain_text):
        ciphertext = ""
        for char in plain_text:
            if char.isalpha():
                if char.islower():
                    char = chr((self.a * (ord(char) - ord('a')) + self.b) % 26 + ord('a'))
                else:
                    char = chr((self.a * (ord(char) - ord('A')) + self.b) % 26 + ord('A'))
            ciphertext += char
        return ciphertext

    def decrypt(self, cipher_text):
        plaintext = ""
        mod_inverse_a = self.mod_inverse(self.a, 26)
        for char in cipher_text:
            if char.isalpha():
                if char.islower():
                    char = chr((mod_inverse_a * (ord(char) - ord('a') - self.b)) % 26 + ord('a'))
                else:
                    char = chr((mod_inverse_a * (ord(char) - ord('A') - self.b)) % 26 + ord('A'))
            plaintext += char
        return plaintext

    def mod_inverse(self, a, m):
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        if x1 < 0:
            x1 += m0
        return x1


class HillCipher:
    def __init__(self, key_matrix):
        self.key_matrix = key_matrix
    
    def prepare_plaintext(self, plaintext):
        num_list = [ord(char) - ord('A') for char in plaintext.upper() if char.isalpha()]
        return num_list
    
    def encrypt(self, plain_text):
        plaintext_nums = self.prepare_plaintext(plain_text)
        if len(plaintext_nums) % 2 != 0:
            plaintext_nums.append(0)
        plaintext_pairs = [[plaintext_nums[i], plaintext_nums[i + 1]] for i in range(0, len(plaintext_nums), 2)]
        ciphertext_pairs = [self.matrix_mult([pair], self.key_matrix, 26)[0] for pair in plaintext_pairs]
        ciphertext = ''.join([chr(pair[0] + ord('A')) + chr(pair[1] + ord('A')) for pair in ciphertext_pairs])
        return ciphertext
    
    def decrypt(self, cipher_text):
        ciphertext_nums = self.prepare_plaintext(cipher_text)
        ciphertext_pairs = [[ciphertext_nums[i], ciphertext_nums[i + 1]] for i in range(0, len(ciphertext_nums), 2)]
        key_matrix_inv = self.matrix_mod_inverse(self.key_matrix, 26)
        plaintext_pairs = [self.matrix_mult([pair], key_matrix_inv, 26)[0] for pair in ciphertext_pairs]
        plaintext = ''.join([chr(pair[0] + ord('A')) + chr(pair[1] + ord('A')) for pair in plaintext_pairs])
        return plaintext
    
    def matrix_mult(self, matrix1, matrix2, m):
        result = [[0] * len(matrix2[0]) for _ in range(len(matrix1))]
        for i in range(len(matrix1)):
            for j in range(len(matrix2[0])):
                for k in range(len(matrix2)):
                    result[i][j] = (result[i][j] + matrix1[i][k] * matrix2[k][j]) % m
        return result
    
    def matrix_mod_inverse(self, matrix, m):
        det = matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
        det_inv = self.mod_inverse(det, m)
        if self.gcd(det, m) != 1:
            raise ValueError("Matrix is not invertible modulo m")
        adj_matrix = [[matrix[1][1], -matrix[0][1]], [-matrix[1][0], matrix[0][0]]]
        inv_matrix = [[(det_inv * adj_matrix[i][j]) % m for j in range(2)] for i in range(2)]
        return inv_matrix
    
    def gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a
    
    def mod_inverse(self, a, m):
        m0, x0, x1 = m, 0, 1
        if m == 1:
            return 0
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        if x1 < 0:
            x1 += m0
        return x1


def main():
    # Example usage of each cipher
    key_columnar_transposition = [2, 1, 3]
    key_substitution = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
    rails = 3
    rot13_cipher = Rot13Cipher()
    affine_cipher = AffineCipher(5, 8)
    key_matrix_hill_cipher = [[3, 2], [5, 7]]
    
    columnar_cipher = ColumnarTranspositionCipher(key_columnar_transposition)
    substitution_cipher = SubstitutionCipher(key_substitution)
    rail_fence_cipher = RailFenceCipher(rails)
    hill_cipher = HillCipher(key_matrix_hill_cipher)
    
    # Test encryption and decryption
    plain_text = "HELLO WORLD"
    
    encrypted_columnar = columnar_cipher.encrypt(plain_text)
    decrypted_columnar = columnar_cipher.decrypt(encrypted_columnar)
    print("Columnar Transposition:")
    print("Encrypted:", encrypted_columnar)
    print("Decrypted:", decrypted_columnar)
    
    encrypted_substitution = substitution_cipher.encrypt(plain_text)
    decrypted_substitution = substitution_cipher.decrypt(encrypted_substitution)
    print("\nSubstitution:")
    print("Encrypted:", encrypted_substitution)
    print("Decrypted:", decrypted_substitution)
    
    encrypted_rail_fence = rail_fence_cipher.encrypt(plain_text)
    decrypted_rail_fence = rail_fence_cipher.decrypt(encrypted_rail_fence)
    print("\nRail Fence:")
    print("Encrypted:", encrypted_rail_fence)
    print("Decrypted:", decrypted_rail_fence)
    
    encrypted_rot13 = rot13_cipher.encrypt(plain_text)
    decrypted_rot13 = rot13_cipher.decrypt(encrypted_rot13)
    print("\nRot13:")
    print("Encrypted:", encrypted_rot13)
    print("Decrypted:", decrypted_rot13)
    
    encrypted_affine = affine_cipher.encrypt(plain_text)
    decrypted_affine = affine_cipher.decrypt(encrypted_affine)
    print("\nAffine:")
    print("Encrypted:", encrypted_affine)
    print("Decrypted:", decrypted_affine)
    
    encrypted_hill = hill_cipher.encrypt(plain_text)
    decrypted_hill = hill_cipher.decrypt(encrypted_hill)
    print("\nHill Cipher:")
    print("Encrypted:", encrypted_hill)
    print("Decrypted:", decrypted_hill)


if __name__ == "__main__":
    main()
