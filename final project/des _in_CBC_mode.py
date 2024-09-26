from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image

# Set the key and the mode for the cipher object
key = b'0123456789abcdef'
mode = AES.MODE_CBC

# Get the input and output image file paths from the user
input_file = "C:\\Users\\mania\\input image\\original image 1.jpg"
output_file = "C:\\Users\\mania\\output image\\output image.bmp"

# Open the image file and convert it to bytes
with open(input_file, 'rb') as f:
    data = f.read()

# Pad the data to the nearest multiple of 16 bytes
padded_data = pad(data, AES.block_size)

# Create a new AES cipher object
cipher = AES.new(key, mode)

# Encrypt the data
ciphertext = cipher.encrypt(padded_data)

# Save the encrypted image to a file
with open(output_file, 'wb') as f:
    f.write(ciphertext)

# Open the encrypted image file and convert it to bytes
with open(output_file, 'rb') as f:
    ciphertext = f.read()

# Create a new AES cipher object
cipher = AES.new(key, mode)

# Decrypt the data
decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)

# Create a PIL image object from the decrypted data
image = Image.frombytes('RGB', (500, 500), decrypted_data)

# Save the decrypted image to a file
image.save('decrypted_image.png')
