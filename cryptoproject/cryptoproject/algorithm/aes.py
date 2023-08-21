import hashlib
import os
import AES

def pad(text):
    padding_size = 16 - len(text) % 16
    padding = bytes([padding_size] * padding_size)
    return text + padding

def unpad(text):
    padding_size = text[-1]
    return text[:-padding_size]

def derive_key_and_iv(password, salt):
    d = d_i = b''
    while len(d) < 48:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d += d_i
    return d[:32], d[32:48]

def encrypt(message, password):
    salt = os.urandom(8)
    key, iv = derive_key_and_iv(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message)
    ciphertext = cipher.encrypt(padded_message)
    return salt + ciphertext

def decrypt(ciphertext, password):
    salt, ciphertext = ciphertext[:8], ciphertext[8:]
    key, iv = derive_key_and_iv(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = cipher.decrypt(ciphertext)
    message = unpad(padded_message)
    return message





