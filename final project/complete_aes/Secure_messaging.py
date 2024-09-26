import sys
import tkinter as tk
#from tkinter import filedialog
import time
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib


def des3_ofb_encryption(file_bytes, key_hash, block_size):
    start_time = time.perf_counter()
    iv = Random.new().read(block_size)
    cipher = DES3.new(key_hash, DES3.MODE_OFB, iv)
    file_bytes = pad(file_bytes, block_size)
    new_file_bytes = cipher.encrypt(file_bytes)
    end_time = time.perf_counter()
    return (new_file_bytes, iv, start_time, end_time)


def des3_ofb_decryption(file_bytes, iv, key_hash, block_size):
    start_time = time.perf_counter()
    cipher = DES3.new(key_hash, DES3.MODE_OFB, iv)
    new_file_bytes = cipher.decrypt(file_bytes)
    new_file_bytes = unpad(new_file_bytes, block_size)
    end_time = time.perf_counter()
    return (new_file_bytes, start_time, end_time)


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


def des3_cfb_encryption(file_bytes, key_hash, block_size):
    start_time = time.perf_counter()
    iv = Random.new().read(block_size)
    cipher = DES3.new(key_hash, DES3.MODE_CFB, iv)
    file_bytes = pad(file_bytes, block_size)
    new_file_bytes = cipher.encrypt(file_bytes)
    end_time = time.perf_counter()
    return (new_file_bytes, iv, start_time, end_time)


def des3_cfb_decryption(file_bytes, iv, key_hash, block_size):
    start_time = time.perf_counter()
    cipher = DES3.new(key_hash, DES3.MODE_CFB, iv)
    new_file_bytes = cipher.decrypt(file_bytes)
    new_file_bytes = unpad(new_file_bytes, block_size)
    end_time = time.perf_counter()
    return (new_file_bytes, start_time, end_time)


def des3_ctr_encryption(file_bytes, key_hash, block_size):
    start_time = time.perf_counter()
    iv = Random.new().read(block_size//8)
    cipher = DES3.new(key_hash, DES3.MODE_CTR, nonce=iv)
    file_bytes = pad(file_bytes, block_size)
    new_file_bytes = cipher.encrypt(file_bytes)
    end_time = time.perf_counter()
    return (new_file_bytes, iv, start_time, end_time)


def des3_ctr_decryption(file_bytes, iv, key_hash, block_size):
    start_time = time.perf_counter()
    cipher = DES3.new(key_hash, DES3.MODE_CTR, nonce=iv)
    new_file_bytes = cipher.decrypt(file_bytes)
    new_file_bytes = unpad(new_file_bytes, block_size)
    end_time = time.perf_counter()
    return (new_file_bytes, start_time, end_time)


def aes_ofb_encryption(file_bytes, key_hash, block_size):
    start_time = time.perf_counter()
    iv = Random.new().read(block_size)
    cipher = AES.new(key_hash, AES.MODE_OFB, iv)
    file_bytes = pad(file_bytes, block_size)
    new_file_bytes = cipher.encrypt(file_bytes)
    end_time = time.perf_counter()
    return (new_file_bytes, iv, start_time, end_time)


def aes_ofb_decryption(file_bytes, iv, key_hash, block_size):
    start_time = time.perf_counter()
    cipher = AES.new(key_hash, AES.MODE_OFB, iv)
    new_file_bytes = cipher.decrypt(file_bytes)
    new_file_bytes = unpad(new_file_bytes, block_size)
    end_time = time.perf_counter()
    return (new_file_bytes, start_time, end_time)


def aes_cbc_encryption(file_bytes, key_hash, block_size):
    start_time = time.perf_counter()
    iv = Random.new().read(block_size)
    cipher = AES.new(key_hash, AES.MODE_CBC, iv)
    file_bytes = pad(file_bytes, block_size)
    new_file_bytes = cipher.encrypt(file_bytes)
    end_time = time.perf_counter()
    return (new_file_bytes, iv, start_time, end_time)


def aes_cbc_decryption(file_bytes, iv, key_hash, block_size):
    start_time = time.perf_counter()
    cipher = AES.new(key_hash, AES.MODE_CBC, iv)
    new_file_bytes = cipher.decrypt(file_bytes)
    new_file_bytes = unpad(new_file_bytes, block_size)
    end_time = time.perf_counter()
    return (new_file_bytes, start_time, end_time)


def aes_cfb_encryption(file_bytes, key_hash, block_size):
    start_time = time.perf_counter()
    iv = Random.new().read(block_size)
    cipher = AES.new(key_hash, AES.MODE_CFB, iv)
    file_bytes = pad(file_bytes, block_size)
    new_file_bytes = cipher.encrypt(file_bytes)
    end_time = time.perf_counter()
    return (new_file_bytes, iv, start_time, end_time)


def aes_cfb_decryption(file_bytes, iv, key_hash, block_size):
    start_time = time.perf_counter()
    cipher = AES.new(key_hash, AES.MODE_CFB, iv)
    new_file_bytes = cipher.decrypt(file_bytes)
    new_file_bytes = unpad(new_file_bytes, block_size)
    end_time = time.perf_counter()
    return (new_file_bytes, start_time, end_time)


def aes_eax_encryption(file_bytes, key_hash, block_size):
    start_time = time.perf_counter()
    iv = Random.new().read(block_size)
    cipher = AES.new(key_hash, AES.MODE_EAX, nonce=iv)
    new_file_bytes = cipher.encrypt(file_bytes)
    end_time = time.perf_counter()
    return (new_file_bytes, iv, start_time, end_time)


def aes_eax_decryption(file_bytes, key_hash, iv):
    start_time = time.perf_counter()
    cipher = AES.new(key_hash, AES.MODE_EAX, nonce=iv)
    new_file_bytes = cipher.decrypt(file_bytes)
    end_time = time.perf_counter()
    return (new_file_bytes, start_time, end_time)


def aes_gcm_encryption(file_bytes, key_hash, block_size):
    start_time = time.perf_counter()
    iv = Random.new().read(block_size)
    cipher = AES.new(key_hash, AES.MODE_GCM, nonce=iv)
    file_bytes = pad(file_bytes, block_size)
    new_file_bytes = cipher.encrypt(file_bytes)
    end_time = time.perf_counter()
    return (new_file_bytes, iv, start_time, end_time)


def aes_gcm_decryption(file_bytes, iv, key_hash, block_size):
    start_time = time.perf_counter()
    cipher = AES.new(key_hash, AES.MODE_GCM, nonce=iv)
    new_file_bytes = cipher.decrypt(file_bytes)
    new_file_bytes = unpad(new_file_bytes, block_size)
    end_time = time.perf_counter()
    return (new_file_bytes, start_time, end_time)


def aes_ctr_encryption(file_bytes, key_hash, block_size):
    start_time = time.perf_counter()
    iv = Random.new().read(block_size//8)
    cipher = AES.new(key_hash, AES.MODE_CTR, nonce=iv)
    file_bytes = pad(file_bytes, block_size)
    new_file_bytes = cipher.encrypt(file_bytes)
    end_time = time.perf_counter()
    return (new_file_bytes, iv, start_time, end_time)


def aes_ctr_decryption(file_bytes, iv, key_hash, block_size):
    start_time = time.perf_counter()
    cipher = AES.new(key_hash, AES.MODE_CTR, nonce=iv)
    new_file_bytes = cipher.decrypt(file_bytes)
    new_file_bytes = unpad(new_file_bytes, block_size)
    end_time = time.perf_counter()
    return (new_file_bytes, start_time, end_time)


# -----------------------------------------------------------------------------------------------


def des3_ofb_mode():
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
        file = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'
        with open(file, 'rb') as file:
            file_bytes = file.read()
            print(b64encode(file_bytes).decode('utf-8'))
        time.sleep(20)
        quit()

    file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'

    iv_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\iv\\tdes_ofb_iv.txt'

    final_file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\results\\tdes_ofb.txt'

    key = input('3DES key: ')

    tdes_key = hashlib.sha256(key.encode('ascii')).digest()[:16]  # 16-byte
    #tdes_key = DES3.adjust_key_parity(key_hash)

    if operation == '1':
        # Encrypt
        with open(file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, iv, encryption_time_start, encryption_time_end = des3_ofb_encryption(
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
        with open(final_file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, decryption_start_time, decryption_end_time = des3_ofb_decryption(
            file_bytes, iv, tdes_key, block_size)
        print("Time lapsed during the process:",
              (decryption_end_time-decryption_start_time)*1000.0, "ms")

    with open(final_file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)


def des3_cbc_mode():
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
        file = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'
        with open(file, 'rb') as file:
            file_bytes = file.read()
            print(b64encode(file_bytes).decode('utf-8'))
        time.sleep(20)
        quit()

    file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'

    iv_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\iv\\tdes_cbc_iv.txt'

    final_file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\results\\tdes_cbc.txt'

    key = input('3DES key: ')

    tdes_key = hashlib.sha256(key.encode('ascii')).digest()[:16]  # 16-byte
    #tdes_key = DES3.adjust_key_parity(key_hash)
    if operation == '1':
        # Encrypt
        with open(file_path, 'rb') as input_file:
            file_bytes = input_file.read()
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
        with open(final_file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, decryption_start_time, decryption_end_time = des3_cbc_decryption(
            file_bytes, iv, tdes_key, block_size)
        print("Time lapsed during the process:",
              (decryption_end_time-decryption_start_time)*1000.0, "ms")

    with open(final_file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)


def des3_cfb_mode():
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
        file = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'
        with open(file, 'rb') as file:
            file_bytes = file.read()
            print(b64encode(file_bytes).decode('utf-8'))
        time.sleep(20)
        quit()

    file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'

    iv_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\iv\\tdes_cfb_iv.txt'

    final_file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\results\\tdes_cfb.txt'

    key = input('3DES key: ')

    tdes_key = hashlib.sha256(key.encode('ascii')).digest()[:16]  # 16-byte
    #tdes_key = DES3.adjust_key_parity(key_hash)

    if operation == '1':
        # Encrypt
        with open(file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, iv, encryption_time_start, encryption_time_end = des3_cfb_encryption(
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
        with open(final_file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, decryption_start_time, decryption_end_time = des3_cfb_decryption(
            file_bytes, iv, tdes_key, block_size)
        print("Time lapsed during the process:",
              (decryption_end_time-decryption_start_time)*1000.0, "ms")

    with open(final_file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)


def des3_ctr_mode():
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
        file = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'
        with open(file, 'rb') as file:
            file_bytes = file.read()
            print(b64encode(file_bytes).decode('utf-8'))
        time.sleep(20)
        quit()

    file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'

    iv_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\iv\\tdes_ctr_iv.txt'

    final_file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\results\\tdes_ctr.txt'

    key = input('3DES key: ')

    tdes_key = hashlib.sha256(key.encode('ascii')).digest()[:16]  # 16-byte
    #tdes_key = DES3.adjust_key_parity(key_hash)

    if operation == '1':
        # Encrypt
        with open(file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, iv, encryption_time_start, encryption_time_end = des3_ctr_encryption(
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
        with open(final_file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, decryption_start_time, decryption_end_time = des3_ctr_decryption(
            file_bytes, iv, tdes_key, block_size)
        print("Time lapsed during the process:",
              (decryption_end_time-decryption_start_time)*1000.0, "ms")

    with open(final_file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)


# --------------------------------------------------------------------------------------------------


def aes_ofb_mode(v):
    block_size = AES.block_size

    root = tk.Tk()
    root.withdraw()
    print('Choose one of the following operations: \n\t1- Encrypt\n\t2- Decrypt\n\t3- read encrypted text')

    operation = input('Your choice: ')
    if operation not in ['1', '2', '3']:
        print("!!!select the appropriate number!!!")
        time.sleep(10)
        quit()

    if operation == '3':
        file = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'
        with open(file, 'rb') as file:
            file_bytes = file.read()
            print(b64encode(file_bytes).decode('utf-8'))
        time.sleep(20)
        quit()

    file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'

    iv_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\iv\\aes_ofb_iv.txt'

    final_file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\results\\aes_ofb.txt'

    key = input('AES key: ')

    key_hash = hashlib.sha256(key.encode('ascii')).digest()[:v]  # 16-byte
    #tdes_key = DES3.adjust_key_parity(key_hash)

    if operation == '1':
        # Encrypt
        with open(file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, iv, encryption_time_start, encryption_time_end = aes_ofb_encryption(
            file_bytes, key_hash, block_size)
        #print(encryption_time_start, encryption_time_end)
        print("Time lapsed during the process:",
              (encryption_time_end-encryption_time_start)*1000.0, "ms")

        with open(iv_path, 'wb') as iv_file:
            iv_file.write(iv)
    else:
        # Decrypt
        with open(iv_path, 'rb') as iv_file:
            iv = iv_file.read()
        with open(final_file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, decryption_start_time, decryption_end_time = aes_ofb_decryption(
            file_bytes, iv, key_hash, block_size)
        print("Time lapsed during the process:",
              (decryption_end_time-decryption_start_time)*1000.0, "ms")

    with open(final_file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)


def aes_gcm_mode(v):
    block_size = AES.block_size

    root = tk.Tk()
    root.withdraw()
    print('Choose one of the following operations: \n\t1- Encrypt\n\t2- Decrypt\n\t3- read encrypted text')

    operation = input('Your choice: ')
    if operation not in ['1', '2', '3']:
        print("!!!select the appropriate number!!!")
        time.sleep(10)
        quit()

    if operation == '3':
        file = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'
        with open(file, 'rb') as file:
            file_bytes = file.read()
            print(b64encode(file_bytes).decode('utf-8'))
        time.sleep(20)
        quit()

    file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'

    iv_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\iv\\aes_gcm_iv.txt'

    final_file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\results\\aes_gcm.txt'

    key = input('AES key: ')

    key_hash = hashlib.sha256(key.encode('ascii')).digest()[:v]  # 16-byte

    if operation == '1':
        # Encrypt
        with open(file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, iv, encryption_time_start, encryption_time_end = aes_gcm_encryption(
            file_bytes, key_hash, block_size)
        #print(encryption_time_start, encryption_time_end)
        print("Time lapsed during the process:",
              (encryption_time_end-encryption_time_start)*1000.0, "ms")

        with open(iv_path, 'wb') as iv_file:
            iv_file.write(iv)
    else:
        # Decrypt
        with open(iv_path, 'rb') as iv_file:
            iv = iv_file.read()
        with open(final_file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, decryption_start_time, decryption_end_time = aes_gcm_decryption(
            file_bytes, iv, key_hash, block_size)
        print("Time lapsed during the process:",
              (decryption_end_time-decryption_start_time)*1000.0, "ms")

    with open(final_file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)


def aes_cbc_mode(v):
    block_size = AES.block_size

    root = tk.Tk()
    root.withdraw()
    print('Choose one of the following operations: \n\t1- Encrypt\n\t2- Decrypt\n\t3- read encrypted text')

    operation = input('Your choice: ')
    if operation not in ['1', '2', '3']:
        print("!!!select the appropriate number!!!")
        time.sleep(10)
        quit()

    if operation == '3':
        file = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'
        with open(file, 'rb') as file:
            file_bytes = file.read()
            print(b64encode(file_bytes).decode('utf-8'))
        time.sleep(20)
        quit()

    file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'

    iv_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\iv\\aes_cbc_iv.txt'

    final_file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\results\\aes_cbc.txt'

    key = input('AES key: ')

    key_hash = hashlib.sha256(key.encode('ascii')).digest()[:v]  # 16-byte

    if operation == '1':
        # Encrypt
        with open(file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, iv, encryption_time_start, encryption_time_end = aes_cbc_encryption(
            file_bytes, key_hash, block_size)
        #print(encryption_time_start, encryption_time_end)
        print("Time lapsed during the process:",
              (encryption_time_end-encryption_time_start)*1000.0, "ms")

        with open(iv_path, 'wb') as iv_file:
            iv_file.write(iv)
    else:
        # Decrypt
        with open(iv_path, 'rb') as iv_file:
            iv = iv_file.read()
        with open(final_file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, decryption_start_time, decryption_end_time = aes_cbc_decryption(
            file_bytes, iv, key_hash, block_size)
        print("Time lapsed during the process:",
              (decryption_end_time-decryption_start_time)*1000.0, "ms")

    with open(final_file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)


def aes_cfb_mode(v):
    block_size = AES.block_size

    root = tk.Tk()
    root.withdraw()
    print('Choose one of the following operations: \n\t1- Encrypt\n\t2- Decrypt\n\t3- read encrypted text')

    operation = input('Your choice: ')
    if operation not in ['1', '2', '3']:
        print("!!!select the appropriate number!!!")
        time.sleep(10)
        quit()

    if operation == '3':
        file = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'
        with open(file, 'rb') as file:
            file_bytes = file.read()
            print(b64encode(file_bytes).decode('utf-8'))
        time.sleep(20)
        quit()

    file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'

    iv_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\iv\\aes_cfb_iv.txt'

    final_file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\results\\aes_cfb.txt'
    key = input('AES key: ')

    key_hash = hashlib.sha256(key.encode('ascii')).digest()[:v]  # 16-byte

    if operation == '1':
        # Encrypt
        with open(file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, iv, encryption_time_start, encryption_time_end = aes_cfb_encryption(
            file_bytes, key_hash, block_size)
        #print(encryption_time_start, encryption_time_end)
        print("Time lapsed during the process:",
              (encryption_time_end-encryption_time_start)*1000.0, "ms")

        with open(iv_path, 'wb') as iv_file:
            iv_file.write(iv)
    else:
        # Decrypt
        with open(iv_path, 'rb') as iv_file:
            iv = iv_file.read()
        with open(final_file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, decryption_start_time, decryption_end_time = aes_cfb_decryption(
            file_bytes, iv, key_hash, block_size)
        print("Time lapsed during the process:",
              (decryption_end_time-decryption_start_time)*1000.0, "ms")

    with open(final_file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)


def aes_eax_mode(v):
    root = tk.Tk()
    root.withdraw()
    print('Choose one of the following operations: \n\t1- Encrypt\n\t2- Decrypt\n\t3- read encrypted text')

    operation = input('Your choice: ')
    if operation not in ['1', '2', '3']:
        print("!!!select the appropriate number!!!")
        quit()

    if operation == '3':
        file = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'
        with open(file, 'rb') as file:
            file_bytes = file.read()
            print(b64encode(file_bytes).decode('utf-8'))
        time.sleep(20)
        quit()

    file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'
    iv_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\iv\\aes_eax_iv.txt'
    final_file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\results\\aes_eax.txt'
    key = input('AES key: ')

    key_hash = hashlib.sha256(key.encode('ascii')).digest()[:v]  # 16-byte
    block_size = AES.block_size

    if operation == '1':
        # Encrypt
        with open(file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, iv, encryption_time_start, encryption_time_end = aes_eax_encryption(
            file_bytes, key_hash, block_size)
        #print(encryption_time_start, encryption_time_end)
        print("Time lapsed during the process:",
              (encryption_time_end-encryption_time_start)*1000.0, "ms")

        with open(iv_path, 'wb') as iv_file:
            iv_file.write(iv)
    else:
        # Decrypt
        with open(iv_path, 'rb') as iv_file:
            iv = iv_file.read()
        with open(final_file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, decryption_start_time, decryption_end_time = aes_eax_decryption(
            file_bytes, key_hash, iv)
        print("Time lapsed during the process:",
              (decryption_end_time-decryption_start_time)*1000.0, "ms")

    with open(final_file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)


def aes_ctr_mode(v):

    block_size = AES.block_size

    root = tk.Tk()
    root.withdraw()
    print('Choose one of the following operations: \n\t1- Encrypt\n\t2- Decrypt\n\t3- read encrypted text')

    operation = input('Your choice: ')
    if operation not in ['1', '2', '3']:
        print("!!!select the appropriate number!!!")
        time.sleep(10)
        quit()

    if operation == '3':
        file = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'
        with open(file, 'rb') as file:
            file_bytes = file.read()
            print(b64encode(file_bytes).decode('utf-8'))
        time.sleep(20)
        quit()

    file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\plain text.txt'

    iv_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\iv\\aes_ctr_iv.txt'

    final_file_path = 'C:\\Users\\mania\\OneDrive\\Desktop\\results\\aes_ctr.txt'

    key = input('AES key: ')

    key_hash = hashlib.sha256(key.encode('ascii')).digest()[:v]  # 16-byte

    if operation == '1':
        # Encrypt
        with open(file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, iv, encryption_time_start, encryption_time_end = aes_ctr_encryption(
            file_bytes, key_hash, block_size)
        #print(encryption_time_start, encryption_time_end)
        print("Time lapsed during the process:",
              (encryption_time_end-encryption_time_start)*1000.0, "ms")

        with open(iv_path, 'wb') as iv_file:
            iv_file.write(iv)
    else:
        # Decrypt
        with open(iv_path, 'rb') as iv_file:
            iv = iv_file.read()
        with open(final_file_path, 'rb') as input_file:
            file_bytes = input_file.read()
        new_file_bytes, decryption_start_time, decryption_end_time = aes_ctr_decryption(
            file_bytes, iv, key_hash, block_size)
        print("Time lapsed during the process:",
              (decryption_end_time-decryption_start_time)*1000.0, "ms")

    with open(final_file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)

# -------------------------------------------------------------------------------------------------


def on_3des_selected():
    root.destroy()
    root2 = tk.Tk()
    root2.title("3des Mode Selection")
    root2.geometry("300x300")  # Set dialog box size
    root2.eval('tk::PlaceWindow . center')
    lbl_mode = tk.Label(root2, text="Mode:\n\n1.CBC\n2.CFB\n3.OFB\n4.CTR\n")
    lbl_mode.pack(pady=5)

    def execute_code(mode):
        root2.destroy()
        if mode == '1':
            des3_cbc_mode()
        elif mode == '2':
            des3_cfb_mode()
        elif mode == '3':
            des3_ofb_mode()
        elif mode == '4':
            des3_ctr_mode()

    for i in range(1, 5):
        btn_mode = tk.Button(root2, text="Mode {}".format(
            i), command=lambda mode=i: execute_code(str(mode)))
        btn_mode.pack(pady=5)

    root2.mainloop()


def on_aes_selected(v):
    root.destroy()
    root2 = tk.Tk()
    root2.title("aes Mode Selection")
    root2.geometry("400x400")  # Set dialog box size
    root2.eval('tk::PlaceWindow . center')
    lbl_mode = tk.Label(
        root2, text="Mode:\n\n1.CBC\n2.CFB\n3.OFB\n4.CTR\n5.EAX\n6.GCM")
    lbl_mode.pack(pady=5)

    def execute_code(mode):
        root2.destroy()
        if mode == '1':
            aes_cbc_mode(v)
        elif mode == '2':
            aes_cfb_mode(v)
        elif mode == '3':
            aes_ofb_mode(v)
        elif mode == '4':
            aes_ctr_mode(v)
        elif mode == '5':
            aes_eax_mode(v)
        elif mode == '6':
            aes_gcm_mode(v)

    btn_mode1 = tk.Button(root2, text="Mode 1",
                          command=lambda mode=1: execute_code(str(mode)))
    btn_mode1.pack(pady=5)

    btn_mode2 = tk.Button(root2, text="Mode 2",
                          command=lambda mode=2: execute_code(str(mode)))
    btn_mode2.pack(pady=5)

    btn_mode3 = tk.Button(root2, text="Mode 3",
                          command=lambda mode=3: execute_code(str(mode)))
    btn_mode3.pack(pady=5)

    btn_mode4 = tk.Button(root2, text="Mode 4",
                          command=lambda mode=4: execute_code(str(mode)))
    btn_mode4.pack(pady=5)

    btn_mode5 = tk.Button(root2, text="Mode 5",
                          command=lambda mode=5: execute_code(str(mode)))
    btn_mode5.pack(pady=5)

    btn_mode6 = tk.Button(root2, text="Mode 6",
                          command=lambda mode=6: execute_code(str(mode)))
    btn_mode6.pack(pady=5)

    root2.mainloop()


def show_algorithm_mode_dialog():
    global root
    root = tk.Tk()
    root.title("Algorithm and Mode Selection")
    root.geometry("300x200")
    root.eval('tk::PlaceWindow . center')
    lbl_algorithm = tk.Label(root, text="Select Algorithm:")
    lbl_algorithm.pack(pady=5)

    btn_algorithm1 = tk.Button(
        root, text="3des", command=on_3des_selected)
    btn_algorithm1.pack(pady=5)

    btn_algorithm2 = tk.Button(
        root, text="aes-128", command=lambda: on_aes_selected(16))
    btn_algorithm2.pack(pady=5)

    btn_algorithm3 = tk.Button(
        root, text="aes-192", command=lambda: on_aes_selected(24))
    btn_algorithm3.pack(pady=5)

    btn_algorithm4 = tk.Button(
        root, text="aes-256", command=lambda: on_aes_selected(32))
    btn_algorithm4.pack(pady=5)

    root.mainloop()


def programm():
    global root1
    root1 = tk.Tk()
    root1.title("Encryption and Decryption")
    root1.geometry("300x200")
    root1.eval('tk::PlaceWindow . center')
    programm_state = tk.Label(root1)
    programm_state.pack(pady=5)

    start_btn = tk.Button(
        root1, text="START", command=lambda: show_algorithm_mode_dialog())
    start_btn.pack(pady=5)

    stop_btn = tk.Button(
        root1, text="STOP", command=lambda: sys.exit(0))
    stop_btn.pack(pady=5)

    root1.mainloop()


programm()
