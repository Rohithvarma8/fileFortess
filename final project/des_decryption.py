import base32hex
import hashlib
from Crypto.Cipher import DES
password = "Password"
salt = '\x28\xAB\xBC\xCD\xDE\xEF\x00\x33'
key = password + salt
m = hashlib.md5(key.encode())
key = m.digest()
(dk, iv) = (key[:8], key[8:])
crypter = DES.new(dk, DES.MODE_CBC, iv)
encrypted_string = input()

print("The ecrypted string is : ", encrypted_string)
encrypted_string = base32hex.b32decode(encrypted_string)
decrypted_string = crypter.decrypt(encrypted_string.encode()).decode('utf-8')
print("The decrypted string is : ", decrypted_string)
