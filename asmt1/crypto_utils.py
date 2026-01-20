import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hmac


# PKCS#7 padding implementation
def pkcs7_pad(data):
    """
    Add PKCS#7 padding to data.
    Padding is always added, even if data is already block-aligned.
    """
    block_size = 16
    padding_length = block_size - (len(data) % block_size)
    
    # Create padding bytes - all bytes equal to padding length
    padding = bytes([padding_length] * padding_length)
    
    return data + padding


def pkcs7_unpad(padded_data):
    """
    Remove PKCS#7 padding from data.
    Returns None if padding is invalid (treated as tampering).
    """
    if len(padded_data) == 0:
        return None
    
    # Last byte tells us padding length
    padding_length = padded_data[-1]
    
    # Validate padding length
    if padding_length < 1 or padding_length > 16:
        return None
    
    if len(padded_data) < padding_length:
        return None
    
    # Check all padding bytes match
    padding_bytes = padded_data[-padding_length:]
    for byte in padding_bytes:
        if byte != padding_length:
            return None
    
    # Remove padding
    return padded_data[:-padding_length]


# AES-128-CBC encryption/decryption
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


# HMAC operations
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


# Key derivation functions
def derive_key(master_key, label):
    """
    Derive a key from master key using label.
    H(master_key || label)
    """
    h = hashlib.sha256()
    h.update(master_key)
    h.update(label.encode('utf-8'))
    return h.digest()[:16]  # AES-128 needs 16 bytes


def evolve_key(current_key, context):
    """
    Evolve key using context data.
    H(current_key || context)
    """
    h = hashlib.sha256()
    h.update(current_key)
    h.update(context)
    return h.digest()[:16]  # AES-128 needs 16 bytes


# Random IV generation
def generate_iv():
    """
    Generate cryptographically secure random IV.
    Returns 16 bytes.
    """
    return os.urandom(16)


# Full encryption procedure
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
    # Step 1: Apply padding
    padded = pkcs7_pad(plaintext)
    
    # Step 2: Generate fresh IV
    iv = generate_iv()
    
    # Step 3: Encrypt
    ciphertext = aes_encrypt(padded, enc_key, iv)
    
    # Step 4: Compute HMAC over header || IV || ciphertext
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
    # Step 1: Verify HMAC first (over header + IV + ciphertext)
    data_to_mac = header_without_iv + iv + ciphertext
    if not verify_hmac(mac_key, data_to_mac, received_hmac):
        return None
    
    # Step 2: Decrypt
    padded_plaintext = aes_decrypt(ciphertext, enc_key, iv)
    
    # Step 3: Remove padding
    plaintext = pkcs7_unpad(padded_plaintext)
    
    return plaintext