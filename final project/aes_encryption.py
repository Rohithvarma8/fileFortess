import time
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode


class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        print('block size:', self.block_size)
        self.key = hashlib.sha256(key.encode()).digest()
        print('hashed key:', self.key)

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        #print('iv is:', iv)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encoded_plain_text = plain_text.encode()
        #print('Encoded plain text is:', encoded_plain_text)
        encrypted_text = cipher.encrypt(encoded_plain_text)
        #print('encrypted text before b64encode:', encrypted_text)
        return b64encode(iv + encrypted_text).decode("utf-8")

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - \
            len(plain_text) % self.block_size
        #print('no.of bytes to pad:', number_of_bytes_to_pad)
        ascii_string = chr(number_of_bytes_to_pad)
        #print('ascii character corresponding to the no.of bytes to pad:', ascii_string)
        padding_str = number_of_bytes_to_pad * ascii_string
        #print('padded string:', padding_str)
        padded_plain_text = plain_text + padding_str
        #print('padded plain text:', padded_plain_text)
        # print(end='\n')
        # print(end='\n')
        return padded_plain_text


key = input('Enter the secret key: ')
obj = AESCipher(key)
plain_text = input('Enter the text: ')
start_time = time.time()
encrypted_text = obj.encrypt(plain_text)
end_time = time.time()
print('encrypted text after encryption:', encrypted_text)
print("Encryption time: {:.4f} seconds".format(end_time - start_time))
