# AES 256 encryption/decryption using pycrypto library
 
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
 
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
 
#hex key passed from js script
private_key = bytearray.fromhex("6cba96607e146a0015b8fd703f7d15375370d6a81d55bb80fae57b89ef68d765")
 

def encrypt(raw):
    raw = pad(raw)
    # iv = Random.new().read(AES.block_size)   <==== How you would create a random IV, I used the same one from the JS script.
    iv = bytes.fromhex("504ce4bd4ed41d7ac97018a3da211fd4")
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    print((cipher.encrypt(raw.encode("utf8"))).hex()) # given the same key and IV, we should get the same hex encrypted message
    return base64.b64encode(iv + cipher.encrypt(raw.encode())) # This is the way that they pass the IV to the decrypt method
 
 
def decrypt(enc):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))
 
 
# First let us encrypt secret message
encrypted = encrypt("testing attention please")
# print(encrypted.hex())

# encrypted = bytes.fromhex("daa118c2a3a54601c1ee08c8f5b0f2c2384c6ca675ac5d19469175133c6743b1")
 
# Let us decrypt using our original password
# decrypted = decrypt(encrypted)
# print(bytes.decode(decrypted))