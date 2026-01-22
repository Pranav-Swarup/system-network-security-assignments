import socket
import struct
import sys
from protocol_fsm import (
    ClientSession, ProtocolState, Opcode, Direction,
    pack_message, unpack_message, advance_round, transition_state
)
from crypto_utils import encrypt_and_authenticate, verify_and_decrypt

class SecureClient:
    def __init__(self, client_id, master_key, server_host='127.0.0.1', server_port=9999):
        self.client_id = client_id
        self.session = ClientSession(client_id, master_key)
        self.server_host = server_host
        self.server_port = server_port
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_host, self.server_port))
        self.sock.settimeout(30.0)
        print(f"[+] Connected to {self.server_host}:{self.server_port}")

    def send_hello(self):
        payload = b"HELLO"
        # Corrected: Use direction-specific getter
        enc_key, mac_key = self.session.get_c2s_keys()

        header = struct.pack('!B B I B', Opcode.CLIENT_HELLO,
            self.client_id, self.session.round_number, Direction.CLIENT_TO_SERVER)

        iv, ciphertext, hmac_tag = encrypt_and_authenticate(payload, enc_key, mac_key, header)

        msg = pack_message(Opcode.CLIENT_HELLO, self.client_id,
            self.session.round_number, Direction.CLIENT_TO_SERVER, iv, ciphertext, hmac_tag)

        self.sock.sendall(msg)
        print(f"[+] Sent CLIENT_HELLO (Round {self.session.round_number})")

        # Corrected: Evolve C2S keys (Ciphertext + Nonce/IV)
        self.session.evolve_c2s_keys(ciphertext, iv)

    def receive_challenge(self):
        try:
            data = self.sock.recv(4096)
        except socket.timeout:
            print("[!] Timeout waiting for Challenge")
            return None

        if not data: return None

        msg = unpack_message(data)
        if not msg or msg['opcode'] != Opcode.SERVER_CHALLENGE:
            print("[!] Invalid Challenge Message")
            return None

        if msg['round'] != self.session.round_number:
            print(f"[!] Round mismatch. Expected {self.session.round_number}, got {msg['round']}")
            return None

        # Corrected: Use direction-specific getter
        enc_key, mac_key = self.session.get_s2c_keys()

        plaintext = verify_and_decrypt(msg['ciphertext'], enc_key, mac_key,
            msg['header'], msg['hmac'], msg['iv'])

        if plaintext is None:
            print("[!] Integrity Check Failed on Challenge")
            return None

        print(f"[+] Received SERVER_CHALLENGE (Round {self.session.round_number})")

        # Corrected: Evolve S2C keys using PLAINTEXT (as per spec requirement fix)
        status_code = b'\x00'
        self.session.evolve_s2c_keys(plaintext, status_code)

        transition_state(self.session, ProtocolState.ACTIVE)
        advance_round(self.session)
        return plaintext

    def send_data(self, value):
        payload = struct.pack('!I', value)
        enc_key, mac_key = self.session.get_c2s_keys()

        header = struct.pack('!B B I B', Opcode.CLIENT_DATA,
            self.client_id, self.session.round_number, Direction.CLIENT_TO_SERVER)

        iv, ciphertext, hmac_tag = encrypt_and_authenticate(payload, enc_key, mac_key, header)

        msg = pack_message(Opcode.CLIENT_DATA, self.client_id,
            self.session.round_number, Direction.CLIENT_TO_SERVER, iv, ciphertext, hmac_tag)

        self.sock.sendall(msg)
        print(f"[+] Sent CLIENT_DATA: {value} (Round {self.session.round_number})")

        # Corrected: Evolve C2S keys
        self.session.evolve_c2s_keys(ciphertext, iv)

    def receive_aggregation(self):
        try:
            data = self.sock.recv(4096)
        except socket.timeout:
            print("[!] Timeout waiting for Aggregation")
            return None
        except Exception as e:
            print(f"[!] Connection error: {e}")
            return None

        if not data:
            print("[!] Connection closed by server")
            return None

        msg = unpack_message(data)
        if not msg or msg['opcode'] != Opcode.SERVER_AGGR_RESPONSE:
            print("[!] Invalid/Unexpected Message")
            return None

        if msg['round'] != self.session.round_number:
            print(f"[!] Round mismatch. Expected {self.session.round_number}, got {msg['round']}")
            return None

        enc_key, mac_key = self.session.get_s2c_keys()
        plaintext = verify_and_decrypt(msg['ciphertext'], enc_key, mac_key,
            msg['header'], msg['hmac'], msg['iv'])

        if plaintext is None:
            print("[!] Integrity Check Failed on Aggregation")
            return None

        agg_value = struct.unpack('!I', plaintext)[0]
        print(f"[+] Received Aggregation: {agg_value} (Round {msg['round']})")

        # Corrected: Evolve S2C keys using PLAINTEXT
        status_code = b'\x00'
        self.session.evolve_s2c_keys(plaintext, status_code)
        advance_round(self.session)
        return agg_value

    def run_single(self, value):
        """Run single data exchange and exit"""
        try:
            self.connect()
            self.send_hello()
            if self.receive_challenge() is None: return
            self.send_data(value)
            if self.receive_aggregation() is None: return
            print("[+] Protocol completed successfully")
        except ConnectionRefusedError:
            print("[!] Connection Refused. Is server running?")
        finally:
            if self.sock: self.sock.close()

    def run_interactive(self):
        """Run interactive mode - multiple data exchanges in one session"""
        try:
            self.connect()
            self.send_hello()

            if self.receive_challenge() is None:
                print("[!] Handshake failed")
                return

            print("\n[+] Handshake complete. Session ACTIVE.")
            print("[*] Enter integers to send (or 'q' to quit)")

            while True:
                try:
                    user_input = input(f"\nRound {self.session.round_number} > ")

                    if user_input.lower() in ['q', 'quit', 'exit']:
                        print("[*] Terminating session...")
                        break

                    try:
                        value = int(user_input)
                    except ValueError:
                        print("[!] Please enter a valid integer")
                        continue

                    self.send_data(value)

                    agg = self.receive_aggregation()
                    if agg is None:
                        print("[!] Protocol error or timeout. Closing.")
                        break

                except KeyboardInterrupt:
                    print("\n[*] Interrupted by user")
                    break
        except ConnectionRefusedError:
             print("[!] Connection Refused. Is server running?")
        finally:
            if self.sock:
                self.sock.close()
                print("[*] Connection closed")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  Single mode:      python client.py <client_id> <master_key_hex> <value>")
        print("  Interactive mode: python client.py <client_id> <master_key_hex> -i")
        sys.exit(1)

    try:
        cid = int(sys.argv[1])
        key = bytes.fromhex(sys.argv[2])
    except ValueError:
        print("[!] Error: Client ID must be int, Key must be hex string")
        sys.exit(1)

    client = SecureClient(cid, key)

    # Check for interactive flag
    if len(sys.argv) > 3 and sys.argv[3] == '-i':
        client.run_interactive()
    else:
        value = int(sys.argv[3]) if len(sys.argv) > 3 else 100
        client.run_single(value)
