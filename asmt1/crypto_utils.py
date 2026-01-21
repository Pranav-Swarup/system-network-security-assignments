import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hmac



def pkcs7_pad(data):
    """
    Add PKCS
    Padding is always added, even if data is already block-aligned.
    """
    block_size = 16
    padding_length = block_size - (len(data) % block_size)
    
    
    padding = bytes([padding_length] * padding_length)
    
    return data + padding


def pkcs7_unpad(padded_data):
    """
    Remove PKCS
    Returns None if padding is invalid (treated as tampering).
    """
    if len(padded_data) == 0:
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
    """
    Encrypt plaintext using AES-128-CBC.
    Plaintext must already be padded.
    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext


def aes_decrypt(ciphertext, key, iv):
    """
    Decrypt ciphertext using AES-128-CBC.
    Returns padded plaintext (padding must be removed separately).
    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext



def compute_hmac(key, data):
    """
    Compute HMAC-SHA256 over data.
    Returns 32-byte digest.
    """
    h = hmac.new(key, data, hashlib.sha256)
    return h.digest()


def verify_hmac(key, data, received_hmac):
    """
    Verify HMAC using constant-time comparison.
    Returns True if valid, False otherwise.
    """
    expected_hmac = compute_hmac(key, data)
    return hmac.compare_digest(expected_hmac, received_hmac)



def derive_key(master_key, label):
    """
    Derive a key from master key using label.
    H(master_key || label)
    """
    h = hashlib.sha256()
    h.update(master_key)
    h.update(label.encode('utf-8'))
    return h.digest()[:16]  


def evolve_key(current_key, context):
    """
    Evolve key using context data.
    H(current_key || context)
    """
    h = hashlib.sha256()
    h.update(current_key)
    h.update(context)
    return h.digest()[:16]  



def generate_iv():
    """
    Generate cryptographically secure random IV.
    Returns 16 bytes.
    """
    return os.urandom(16)



def encrypt_and_authenticate(plaintext, enc_key, mac_key, header_without_iv):
    """
    Complete encryption procedure:
    1. Pad plaintext
    2. Generate IV
    3. Encrypt with AES-CBC
    4. Compute HMAC over (header + IV + ciphertext)
    
    Returns (iv, ciphertext, hmac_tag)
    Note: header_without_iv should NOT include the IV
    """
    
    padded = pkcs7_pad(plaintext)
    
    
    iv = generate_iv()
    
    
    ciphertext = aes_encrypt(padded, enc_key, iv)
    
    
    data_to_mac = header_without_iv + iv + ciphertext
    hmac_tag = compute_hmac(mac_key, data_to_mac)
    
    return iv, ciphertext, hmac_tag


def verify_and_decrypt(ciphertext, enc_key, mac_key, header_without_iv, received_hmac, iv):
    """
    Complete decryption procedure:
    1. Verify HMAC BEFORE decryption
    2. Decrypt if HMAC valid
    3. Remove padding
    4. Return plaintext or None on failure
    
    Returns plaintext or None
    Note: header_without_iv should NOT include the IV
    """
    
    data_to_mac = header_without_iv + iv + ciphertext
    if not verify_hmac(mac_key, data_to_mac, received_hmac):
        return None
    
    
    padded_plaintext = aes_decrypt(ciphertext, enc_key, iv)
    
    
    plaintext = pkcs7_unpad(padded_plaintext)
    
    return plaintext