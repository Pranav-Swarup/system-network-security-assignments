import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def pkcs7_pad(data):
    block_size = 16
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(padded_data):
    if not padded_data or len(padded_data) == 0:
        return None

    padding_length = padded_data[-1]
    if padding_length < 1 or padding_length > 16:
        return None
    if len(padded_data) < padding_length:
        return None

    padding_bytes = padded_data[-padding_length:]
    for byte in padding_bytes:
        if byte != padding_length:
            return None

    return padded_data[:-padding_length]

def aes_encrypt(plaintext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def aes_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def compute_hmac(key, data):
    h = hmac.new(key, data, hashlib.sha256)
    return h.digest()

def verify_hmac(key, data, received_hmac):
    expected_hmac = compute_hmac(key, data)
    return hmac.compare_digest(expected_hmac, received_hmac)

def derive_key(master_key, label):
    h = hashlib.sha256()
    h.update(master_key)
    h.update(label.encode('utf-8'))
    return h.digest()[:16]

def evolve_key(current_key, context):
    h = hashlib.sha256()
    h.update(current_key)
    h.update(context)
    return h.digest()[:16]

def generate_iv():
    return os.urandom(16)

def encrypt_and_authenticate(plaintext, enc_key, mac_key, header_without_iv):
    padded = pkcs7_pad(plaintext)
    iv = generate_iv()
    ciphertext = aes_encrypt(padded, enc_key, iv)
    data_to_mac = header_without_iv + iv + ciphertext
    hmac_tag = compute_hmac(mac_key, data_to_mac)
    return iv, ciphertext, hmac_tag

def verify_and_decrypt(ciphertext, enc_key, mac_key, header_without_iv, received_hmac, iv):
    data_to_mac = header_without_iv + iv + ciphertext
    if not verify_hmac(mac_key, data_to_mac, received_hmac):
        return None
    padded_plaintext = aes_decrypt(ciphertext, enc_key, iv)
    plaintext = pkcs7_unpad(padded_plaintext)
    return plaintext
