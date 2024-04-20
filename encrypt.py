# Kenneth Choi & Cole Turner 

import sys
import random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long

def task1():
    # defining secure random number generator
    rand = random.SystemRandom()

    # TODO: change to 1024-bit parameter
    # q = 37
    # alpha = 5
    q = bytes_to_long(bytes.fromhex('B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371'))
    alpha = bytes_to_long(bytes.fromhex('A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213 160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1 909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 855E6EEB 22B3B2E5'))

    # Alice random number
    xa = rand.randint(0, q - 1)

    # Bob random number
    xb = rand.randint(0, q - 1)

    # Alice public key
    aPublic = pow(alpha, xa, q)
    print(f'aPublic: {aPublic}')
    
    # Bob public key
    bPublic = pow(alpha, xb, q)
    print(f'bPublic: {bPublic}')
    
    # Alice private key
    aSecret = pow(bPublic, xa, q)
    print(f'aSecret: {aSecret}')
    
    # Bob private key
    bSecret = pow(aPublic, xb, q)
    print(f'bSecret: {bSecret}')

    # check that the secret keys are the same
    assert aSecret == bSecret, "Secret keys are not the same"  

    # Generate SHA256 hash of the secret key
    hash = SHA256.new()
    hash.update(str(aSecret).encode()) # converts the secret to bytes

    # Generate AES key
    aes_key = hash.digest()[:16] # 16 bytes = 128 bits

    # Create AES cipher and IV
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv

    # Example message
    msg0 = "Hi Bob!"
    msg1 = "Hi Alice!"

    # Encrypt message
    ciphertext0 = cipher.encrypt(pad(msg0.encode(), AES.block_size))
    ciphertext1 = cipher.encrypt(pad(msg1.encode(), AES.block_size))

    # Send ciphertext and IV to Bob
    print(f'iv: {iv}')
    print(f'ciphertext0: {ciphertext0}')

    # Send ciphertext and IV to Alice
    print(f'iv: {iv}')
    print(f'ciphertext1: {ciphertext1}')

    # Decrypt Message
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext0 = unpad(cipher.decrypt(ciphertext0), AES.block_size)
    plaintext1 = unpad(cipher.decrypt(ciphertext1), AES.block_size)

    print(f'plaintext0: {plaintext0}')
    print(f'plaintext1: {plaintext1}')
    return

if __name__ == "__main__":
    task1()