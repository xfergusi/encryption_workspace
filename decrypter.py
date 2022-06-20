# AES 256 encryption/decryption using pycrypto library
 
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
 
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
 
private_key = bytearray.fromhex("16691a3ad4b2449aa0895bf1768a3b9cfbae3c24992df7482cc215dbb9881330")
 

def encrypt(raw):
    raw = pad(raw)
    # iv = Random.new().read(AES.block_size)
    iv = bytes.fromhex("72de0ba2966617fdda284a8d99f3ab9d")
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    # return base64.b64encode(iv + cipher.encrypt(raw.encode("utf8")))
    print((cipher.encrypt(raw.encode("utf8"))).hex())
    return base64.b64encode(cipher.encrypt(raw.encode("utf8")))
 
 
def decrypt(enc):
    # enc = base64.b64decode(enc)
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