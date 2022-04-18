from Crypto.Cipher import AES
from Crypto import Random
import hashlib
BS = AES.block_size
pad = lambda s: s+(BS -len(s)%BS) * chr(BS-len(s) % BS)
txt = "Hello world!"
key = hashlib.sha256(b"155").digest()
txt = pad(txt)
iv = Random.new().read(BS)
cipher = AES.new(key, AES.MODE_CBC, iv)
cipher_txt = (iv + cipher.encrypt(txt.encode()))
print("Ciphertext: ", cipher_txt)
print("Decryption...")
for x in range(100, 999):
    unpad = lambda s_: s_[:-ord (s_[len(s_)-1:])]
    key2 = hashlib.sha256(str(x).encode('utf8')).digest()    
    
    iv = cipher_txt[:BS]
    cipher = AES.new(key2, AES.MODE_CBC, iv)
    txt = unpad(cipher.decrypt(cipher_txt[BS:]))
    if txt !=b'':
        print ('Deciphered text: ' ,txt)
    else:
        print ('error')
