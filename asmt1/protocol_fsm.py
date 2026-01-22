from enum import Enum
import struct
from crypto_utils import derive_key, evolve_key

class ProtocolState(Enum):
    INIT = 0
    ACTIVE = 1
    TERMINATED = 2

class Opcode:
    CLIENT_HELLO = 10
    SERVER_CHALLENGE = 20
    CLIENT_DATA = 30
    SERVER_AGGR_RESPONSE = 40
    KEY_DESYNC_ERROR = 50
    TERMINATE = 60

class Direction:
    CLIENT_TO_SERVER = 0x01
    SERVER_TO_CLIENT = 0x02

class ClientSession:
    def __init__(self, client_id, master_key):
        self.client_id = client_id
        self.round_number = 0
        self.state = ProtocolState.INIT

        # Derive initial keys
        self.c2s_enc_key = derive_key(master_key, "C2S-ENC")
        self.c2s_mac_key = derive_key(master_key, "C2S-MAC")
        self.s2c_enc_key = derive_key(master_key, "S2C-ENC")
        self.s2c_mac_key = derive_key(master_key, "S2C-MAC")

    def get_c2s_keys(self):
        """Keys used for messages going Client -> Server."""
        return self.c2s_enc_key, self.c2s_mac_key

    def get_s2c_keys(self):
        """Keys used for messages going Server -> Client."""
        return self.s2c_enc_key, self.s2c_mac_key

    def evolve_c2s_keys(self, ciphertext, nonce):
        """
        Evolve C2S keys using Ciphertext (per spec).
        C2S_Enc_{R+1} = H(C2S_Enc_R || Ciphertext_R)
        """
        self.c2s_enc_key = evolve_key(self.c2s_enc_key, ciphertext)
        self.c2s_mac_key = evolve_key(self.c2s_mac_key, nonce)

    def evolve_s2c_keys(self, aggregated_data, status_code):
        """
        Evolve S2C keys using Plaintext Data (per spec).
        S2C_Enc_{R+1} = H(S2C_Enc_R || AggregatedData_R)
        """
        self.s2c_enc_key = evolve_key(self.s2c_enc_key, aggregated_data)
        self.s2c_mac_key = evolve_key(self.s2c_mac_key, status_code)

    def terminate(self):
        self.state = ProtocolState.TERMINATED

    def is_terminated(self):
        return self.state == ProtocolState.TERMINATED

def pack_message(opcode, client_id, round_num, direction, iv, ciphertext, hmac_tag):
    header = struct.pack('!B B I B', opcode, client_id, round_num, direction)
    return header + iv + ciphertext + hmac_tag

def unpack_message(message):
    if len(message) < 55: # Min size check
        return None

    opcode, client_id, round_num, direction = struct.unpack('!B B I B', message[0:7])
    iv = message[7:23]
    hmac_tag = message[-32:]
    ciphertext = message[23:-32]
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
    if session.is_terminated(): return False
    if round_num != session.round_number: return False
    if direction != expected_direction: return False

    if session.state == ProtocolState.INIT:
        return opcode == Opcode.CLIENT_HELLO
    elif session.state == ProtocolState.ACTIVE:
        return opcode in [Opcode.CLIENT_DATA, Opcode.TERMINATE]

    return False

def advance_round(session):
    session.round_number += 1

def transition_state(session, new_state):
    session.state = new_state
