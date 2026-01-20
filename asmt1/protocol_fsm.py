from enum import Enum
import struct
from crypto_utils import derive_key, evolve_key


# Protocol states
class ProtocolState(Enum):
    INIT = 0
    ACTIVE = 1
    TERMINATED = 2


# Protocol opcodes
class Opcode:
    CLIENT_HELLO = 10
    SERVER_CHALLENGE = 20
    CLIENT_DATA = 30
    SERVER_AGGR_RESPONSE = 40
    KEY_DESYNC_ERROR = 50
    TERMINATE = 60


# Message direction
class Direction:
    CLIENT_TO_SERVER = 0x01
    SERVER_TO_CLIENT = 0x02


# Client session state
class ClientSession:
    def __init__(self, client_id, master_key):
        self.client_id = client_id
        self.round_number = 0
        self.state = ProtocolState.INIT
        
        # Derive initial keys from master key
        self.c2s_enc_key = derive_key(master_key, "C2S-ENC")
        self.c2s_mac_key = derive_key(master_key, "C2S-MAC")
        self.s2c_enc_key = derive_key(master_key, "S2C-ENC")
        self.s2c_mac_key = derive_key(master_key, "S2C-MAC")
    
    def get_recv_keys(self):
        """Get keys for receiving messages (C2S direction for server)."""
        return self.c2s_enc_key, self.c2s_mac_key
    
    def get_send_keys(self):
        """Get keys for sending messages (S2C direction for server)."""
        return self.s2c_enc_key, self.s2c_mac_key
    
    def evolve_recv_keys(self, ciphertext, nonce):
        """
        Evolve C2S keys after receiving valid message.
        Only call after successful verification!
        """
        self.c2s_enc_key = evolve_key(self.c2s_enc_key, ciphertext)
        self.c2s_mac_key = evolve_key(self.c2s_mac_key, nonce)
    
    def evolve_send_keys(self, aggregated_data, status_code):
        """
        Evolve S2C keys after sending message.
        Only call after successful send!
        """
        self.s2c_enc_key = evolve_key(self.s2c_enc_key, aggregated_data)
        self.s2c_mac_key = evolve_key(self.s2c_mac_key, status_code)
    
    def terminate(self):
        """Permanently terminate this session."""
        self.state = ProtocolState.TERMINATED
    
    def is_terminated(self):
        """Check if session is terminated."""
        return self.state == ProtocolState.TERMINATED


# Message format functions
def pack_message(opcode, client_id, round_num, direction, iv, ciphertext, hmac_tag):
    """
    Pack message into wire format:
    | Opcode (1) | Client ID (1) | Round (4) | Direction (1) | IV (16) |
    | Ciphertext (variable) | HMAC (32) |
    """
    header = struct.pack('!B B I B', opcode, client_id, round_num, direction)
    message = header + iv + ciphertext + hmac_tag
    return message


def unpack_message(message):
    """
    Unpack message from wire format.
    Returns dict with fields or None if invalid.
    """
    # Minimum message size: 1+1+4+1+16+32 = 55 bytes
    if len(message) < 55:
        return None
    
    # Parse fixed header
    opcode, client_id, round_num, direction = struct.unpack('!B B I B', message[0:7])
    
    # Extract IV (16 bytes after header)
    iv = message[7:23]
    
    # Extract HMAC (last 32 bytes)
    hmac_tag = message[-32:]
    
    # Extract ciphertext (between IV and HMAC)
    ciphertext = message[23:-32]
    
    # Build header for HMAC verification (everything before ciphertext)
    header = message[0:7]
    
    return {
        'opcode': opcode,
        'client_id': client_id,
        'round': round_num,
        'direction': direction,
        'iv': iv,
        'ciphertext': ciphertext,
        'hmac': hmac_tag,
        'header': header
    }


def validate_message_state(session, opcode, round_num, direction, expected_direction):
    """
    Validate message against current session state.
    Returns True if valid, False otherwise.
    """
    # Check if session is terminated
    if session.is_terminated():
        return False
    
    # Check round number matches expected
    if round_num != session.round_number:
        return False
    
    # Check direction is correct
    if direction != expected_direction:
        return False
    
    # Validate opcode for current state
    if session.state == ProtocolState.INIT:
        # In INIT state, only CLIENT_HELLO is valid from client
        if opcode != Opcode.CLIENT_HELLO:
            return False
    elif session.state == ProtocolState.ACTIVE:
        # In ACTIVE state, CLIENT_DATA is valid from client
        valid_opcodes = [Opcode.CLIENT_DATA, Opcode.TERMINATE]
        if opcode not in valid_opcodes:
            return False
    else:
        return False
    
    return True


def advance_round(session):
    """Increment round number after successful message exchange."""
    session.round_number += 1


def transition_state(session, new_state):
    """Transition to new protocol state."""
    session.state = new_state