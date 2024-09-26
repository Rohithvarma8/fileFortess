import time
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import hashlib
import tkinter as tk
from tkinter import filedialog


def des3_cbc_encryption(file_bytes, key_hash, block_size):
    start_time = time.perf_counter()
    iv = Random.new().read(block_size)
    cipher = DES3.new(key_hash, DES3.MODE_CBC, iv)
    file_bytes = pad(file_bytes, block_size)
    new_file_bytes = cipher.encrypt(file_bytes)
    end_time = time.perf_counter()
    return (new_file_bytes, iv, start_time, end_time)


def des3_cbc_decryption(file_bytes, iv, key_hash, block_size):
    start_time = time.perf_counter()
    cipher = DES3.new(key_hash, DES3.MODE_CBC, iv)
    new_file_bytes = cipher.decrypt(file_bytes)
    new_file_bytes = unpad(new_file_bytes, block_size)
    end_time = time.perf_counter()
    return (new_file_bytes, start_time, end_time)


block_size = DES3.block_size


root = tk.Tk()
root.withdraw()
print('Choose one of the following operations: \n\t1- Encrypt\n\t2- Decrypt\n\t3- read encrypted text')

operation = input('Your choice: ')
if operation not in ['1', '2', '3']:
    print("!!!select the appropriate number!!!")
    time.sleep(10)
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

iv_path = filedialog.askopenfilename(
    initialdir='C:\\', filetypes=[('All files', '*.*')])

key = input('3DES key: ')

tdes_key = hashlib.sha512(key.encode('ascii')).digest()[:16]  # 16-byte
#tdes_key = DES3.adjust_key_parity(key_hash)

if file_path:
    with open(file_path, 'rb') as input_file:
        file_bytes = input_file.read()
        if operation == '1':
            # Encrypt
            new_file_bytes, iv, encryption_time_start, encryption_time_end = des3_cbc_encryption(
                file_bytes, tdes_key, block_size)
            #print(encryption_time_start, encryption_time_end)
            print("Time lapsed during the process:",
                  (encryption_time_end-encryption_time_start)*1000.0, "ms")
            with open(iv_path, 'wb') as iv_file:
                iv_file.write(iv)
        else:
            # Decrypt
            with open(iv_path, 'rb') as iv_file:
                iv = iv_file.read()
                new_file_bytes, decryption_start_time, decryption_end_time = des3_cbc_decryption(
                    file_bytes, iv, tdes_key, block_size)
                #print(decryption_start_time, decryption_end_time)
                print("Time lapsed during the process:",
                      (decryption_end_time-decryption_start_time)*1000.0, "ms")

    with open(file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)
else:
    print("!!!select a file!!!")
