import socket
import threading
import struct
import os
from protocol_fsm import (
    ClientSession, ProtocolState, Opcode, Direction,
    pack_message, unpack_message, validate_message_state,
    advance_round, transition_state
)
from crypto_utils import encrypt_and_authenticate, verify_and_decrypt

class SecureServer:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.lock = threading.Lock()
        self.round_data = {}  # round_num -> {client_id: value}
        self.seen_ivs = set() # Global IV cache for replay protection

        # Hardcoded for lab assignment purposes
        self.master_keys = {
            1: bytes.fromhex("a1b2c3d4e5f67890a1b2c3d4e5f67890"),
            2: bytes.fromhex("b1b2c3d4e5f67890a1b2c3d4e5f67890"),
            3: bytes.fromhex("c1b2c3d4e5f67890a1b2c3d4e5f67890"),
        }

    def get_master_key(self, client_id):
        return self.master_keys.get(client_id)

    def check_and_store_iv(self, iv):
        with self.lock:
            if iv in self.seen_ivs:
                return False
            self.seen_ivs.add(iv)
            return True

    def handle_client_hello(self, session, msg_data):
        print(f"[{session.client_id}] Processing CLIENT_HELLO...")

        # Replay/Reuse Check
        if not self.check_and_store_iv(msg_data['iv']):
            print(f"[!] [{session.client_id}] IV Reuse/Replay detected!")
            session.terminate()
            return None, None

        enc_key, mac_key = session.get_c2s_keys()

        plaintext = verify_and_decrypt(
            msg_data['ciphertext'], enc_key, mac_key,
            msg_data['header'], msg_data['hmac'], msg_data['iv']
        )

        if plaintext is None:
            print(f"[!] [{session.client_id}] HMAC verification failed for HELLO")
            session.terminate()
            return None, None

        # Evolve C2S Keys (Ciphertext based)
        session.evolve_c2s_keys(msg_data['ciphertext'], msg_data['iv'])

        # Send Challenge
        challenge_nonce = os.urandom(16)
        enc_key, mac_key = session.get_s2c_keys()

        header_data = struct.pack('!B B I B', Opcode.SERVER_CHALLENGE,
                                  session.client_id, session.round_number,
                                  Direction.SERVER_TO_CLIENT)

        iv, ciphertext, hmac_tag = encrypt_and_authenticate(
            challenge_nonce, enc_key, mac_key, header_data
        )

        response = pack_message(
            Opcode.SERVER_CHALLENGE, session.client_id, session.round_number,
            Direction.SERVER_TO_CLIENT, iv, ciphertext, hmac_tag
        )

        # Evolve S2C Keys (Plaintext based - Challenge Nonce acts as data)
        status_code = b'\x00' # Success status
        session.evolve_s2c_keys(challenge_nonce, status_code)

        transition_state(session, ProtocolState.ACTIVE)
        advance_round(session)

        print(f"[+] [{session.client_id}] HELLO successful, sent CHALLENGE")
        return response, challenge_nonce

    def handle_client_data(self, session, msg_data):
        # Replay/Reuse Check
        if not self.check_and_store_iv(msg_data['iv']):
            print(f"[!] [{session.client_id}] IV Reuse/Replay detected in DATA!")
            session.terminate()
            return None

        enc_key, mac_key = session.get_c2s_keys()

        plaintext = verify_and_decrypt(
            msg_data['ciphertext'], enc_key, mac_key,
            msg_data['header'], msg_data['hmac'], msg_data['iv']
        )

        if plaintext is None:
            print(f"[!] [{session.client_id}] HMAC verification failed for DATA")
            session.terminate()
            return None

        if len(plaintext) < 4:
            session.terminate()
            return None

        client_value = struct.unpack('!I', plaintext[:4])[0]
        print(f"[+] [{session.client_id}] Received Data: {client_value} (Round {msg_data['round']})")

        with self.lock:
            if msg_data['round'] not in self.round_data:
                self.round_data[msg_data['round']] = {}
            self.round_data[msg_data['round']][session.client_id] = client_value

        # Evolve C2S keys
        session.evolve_c2s_keys(msg_data['ciphertext'], msg_data['iv'])

        return client_value

    def send_aggregation(self, session, aggregated_value, conn):
        payload = struct.pack('!I', aggregated_value)
        enc_key, mac_key = session.get_s2c_keys()

        header_data = struct.pack('!B B I B', Opcode.SERVER_AGGR_RESPONSE,
                                  session.client_id, session.round_number,
                                  Direction.SERVER_TO_CLIENT)

        iv, ciphertext, hmac_tag = encrypt_and_authenticate(
            payload, enc_key, mac_key, header_data
        )

        response = pack_message(
            Opcode.SERVER_AGGR_RESPONSE, session.client_id, session.round_number,
            Direction.SERVER_TO_CLIENT, iv, ciphertext, hmac_tag
        )

        # Evolve S2C Keys (Plaintext based)
        status_code = b'\x00'
        session.evolve_s2c_keys(payload, status_code)

        conn.sendall(response)
        print(f"[+] [{session.client_id}] Sent Result: {aggregated_value}")
        advance_round(session)

    def handle_connection(self, conn, addr):
        conn.settimeout(5.0)
        session = None
        try:
            # 1. Receive HELLO
            data = conn.recv(4096)
            if not data: return

            msg = unpack_message(data)
            if not msg: return

            client_id = msg['client_id']
            master_key = self.get_master_key(client_id)

            if not master_key:
                print(f"[!] Unknown Client ID: {client_id}")
                return

            session = ClientSession(client_id, master_key)

            if not validate_message_state(session, msg['opcode'], msg['round'],
                                          msg['direction'], Direction.CLIENT_TO_SERVER):
                print(f"[!] [{client_id}] Invalid HELLO State/Direction")
                session.terminate()
                return

            if msg['opcode'] == Opcode.CLIENT_HELLO:
                resp, _ = self.handle_client_hello(session, msg)
                if not resp: return
                conn.sendall(resp)

            # 2. Main Loop
            conn.settimeout(30.0)
            while not session.is_terminated():
                try:
                    data = conn.recv(4096)
                    if not data: break
                except socket.timeout: break

                msg = unpack_message(data)
                if not msg:
                    session.terminate()
                    break

                if not validate_message_state(session, msg['opcode'], msg['round'],
                                              msg['direction'], Direction.CLIENT_TO_SERVER):
                    print(f"[!] [{client_id}] Invalid State/Round/Opcode")
                    session.terminate()
                    break

                if msg['opcode'] == Opcode.CLIENT_DATA:
                    val = self.handle_client_data(session, msg)
                    if val is None: break

                    agg = self.compute_aggregation(msg['round'])
                    self.send_aggregation(session, agg, conn)
                elif msg['opcode'] == Opcode.TERMINATE:
                    print(f"[*] [{client_id}] Terminated by client")
                    session.terminate()
                    break
        except Exception as e:
            if session:
                print(f"[!] [{session.client_id}] Error: {e}")
                session.terminate()
        finally:
            conn.close()

    def compute_aggregation(self, round_num):
        with self.lock:
            if round_num in self.round_data:
                return sum(self.round_data[round_num].values())
            return 0

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(5)
        print(f"[*] Server listening on {self.host}:{self.port}")
        print("[*] Test Keys:")
        for k, v in self.master_keys.items():
            print(f"  Client {k}: {v.hex()}")

        while True:
            try:
                conn, addr = s.accept()
                t = threading.Thread(target=self.handle_connection, args=(conn, addr))
                t.daemon = True
                t.start()
            except KeyboardInterrupt:
                break
        s.close()

if __name__ == "__main__":
    SecureServer().start()
