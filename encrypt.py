# Kenneth Choi & Cole Turner 

import sys
import random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long, getPrime
from Crypto.Random import get_random_bytes
import binascii

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

def task2():
    # defining secure random number generator
    rand = random.SystemRandom()

    q = bytes_to_long(bytes.fromhex('B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371'))
    alpha = bytes_to_long(bytes.fromhex('A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213 160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1 909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 855E6EEB 22B3B2E5'))

    # Mallory sets alpha to 1
    # by setting the alpha to 1, Mallory is effectively changing all the public keys to 1
    alpha = 1

    xa = rand.randint(0, q - 1)
    xb = rand.randint(0, q - 1)

    aPublic = pow(alpha, xa, q)
    bPublic = pow(alpha, xb, q)
    
    # MAN IN THE MIDDLE ATTACK
    print(f"Mallory intercepted aPublic: {aPublic}")
    print(f"Mallory intercepted bPublic: {bPublic}")

    # Mallory determines secret keys
    print(f"Mallory determines secret aSecret: {pow(aPublic, xb, q)}")
    print(f"Mallory determines secret bSecret: {pow(bPublic, xa, q)}")

    # aPublic = q
    # bPublic = q

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

def gcd(e, phi):
    if e == 0:
        return(phi, 0, 1)
    else:
        g, x, y = gcd(phi % e, e)
        return (g, y - (phi // e) * x, x)
    
def inverse(e, phi):
    g, x, _ = gcd(e, phi)
    if g != 1:
        raise Exception('Mod inverse does not exist')
    else:
        return x % phi

def task3():
    #generating keys
    p = getPrime(2048)
    q = getPrime(2048)
    n = p * q 
    phi = (p - 1) * (q - 1)
    e = 65537
    d = inverse(e, phi)
    public_key = (e, n)
    private_key = (d, n)

    #encryption
    msg = "Hello there"

    m = int(binascii.hexlify(msg.encode()), 16)
    ciphertext = pow(m, public_key[0], public_key[1])
    print("Ciphertext: ", ciphertext)

    #decryption
    m = pow(ciphertext, private_key[0], private_key[1])
    plaintext = binascii.unhexlify(hex(m)[2:]).decode()
    print("Plaintext: ", plaintext)

    #part 2
    s = getPrime(2048)
    c = pow(s, e, n)

    #Mallory
    t = getPrime(2048)
    c_prime = pow(t, e, n)

    #Alice receives c_prime
    s_dec = pow(c_prime, d, n)
    sha = SHA256.new()
    sha.update(s_dec.to_bytes((s_dec.bit_length() + 7) // 8, byteorder='big'))
    k = sha.digest()

    m = b"Hi Bob!"
    iv = get_random_bytes(AES.block_size)
    c0 = (AES.new(k, AES.MODE_CBC, iv)).encrypt(pad(m, AES.block_size))

    sha = SHA256.new()
    sha.update(t.to_bytes((t.bit_length() + 7) // 8, byteorder='big'))
    k = sha.digest()

    decrypted_message = unpad((AES.new(k, AES.MODE_CBC, iv)).decrypt(c0), AES.block_size)
    print("Original s: ", s)
    print("Mallory's t: ", t)
    print("Decrypted s (should be t): ", s_dec)
    print("c0: ", c0.hex())
    print("Decrypted message by Mallory: ", decrypted_message.decode())

if __name__ == "__main__":
    print("\n\n\t RUNNING TASK 1 \n\n")
    task1()
    print("\n\n\t RUNNING TASK 2 \n\n")
    task2()
    print("\n\n\t RUNNING TASK 3 \n\n")
    task3()