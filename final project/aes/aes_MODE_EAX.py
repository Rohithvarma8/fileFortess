import time
from Crypto.Cipher import AES
from base64 import b64encode
from hashlib import md5
import tkinter as tk
from tkinter import filedialog


def aes_eax_encryption(file_bytes, key_hash):
    start_time = time.perf_counter()
    cipher = AES.new(key_hash, AES.MODE_EAX, nonce=b'0')
    new_file_bytes = cipher.encrypt(file_bytes)
    end_time = time.perf_counter()
    return (new_file_bytes, start_time, end_time)


def aes_eax_decryption(file_bytes, key_hash):
    start_time = time.perf_counter()
    cipher = AES.new(key_hash, AES.MODE_EAX, nonce=b'0')
    new_file_bytes = cipher.decrypt(file_bytes)
    end_time = time.perf_counter()
    return (new_file_bytes, start_time, end_time)


root = tk.Tk()
root.withdraw()
print('Choose one of the following operations: \n\t1- Encrypt\n\t2- Decrypt\n\t3- read encrypted text')

operation = input('Your choice: ')
if operation not in ['1', '2', '3']:
    print("!!!select the appropriate number!!!")
    quit()

if operation == '3':
    file = filedialog.askopenfilename(
        initialdir='C:\\', filetypes=[('All files', '*.*')])
    with open(file, 'rb') as file:
        file_bytes = file.read()
        print(b64encode(file_bytes).decode('utf-8'))
    time.sleep(20)
    quit()

file_path = filedialog.askopenfilename(
    initialdir='C:\\', filetypes=[('All files', '*.*')])
key = input('AES key: ')

key_hash = md5(key.encode('ascii')).digest()  # 16-byte


if file_path:
    with open(file_path, 'rb') as input_file:
        file_bytes = input_file.read()

        if operation == '1':
            # Encrypt
            new_file_bytes, encryption_time_start, encryption_time_end = aes_eax_encryption(
                file_bytes, key_hash)
            print("Time lapsed during the process:",
                  (encryption_time_end-encryption_time_start)*1000.0, "ms")
        else:
            # Decrypt
            new_file_bytes, decryption_start_time, decryption_end_time = aes_eax_decryption(
                file_bytes, key_hash)
            print("Time lapsed during the process:",
                  (decryption_end_time-decryption_start_time)*1000.0, "ms")
    with open(file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)
else:
    print("!!!select a file!!!")
