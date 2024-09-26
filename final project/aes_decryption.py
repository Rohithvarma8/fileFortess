import hashlib
from Crypto.Cipher import AES
from base64 import b64decode


class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(
            encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]


key = input('Enter the secret key: ')
obj = AESCipher(key)
encrypted_text = input('Enter the Encrypted text:')
decrypted_text = obj.decrypt(encrypted_text)
print("The decrypted text is:", decrypted_text)
