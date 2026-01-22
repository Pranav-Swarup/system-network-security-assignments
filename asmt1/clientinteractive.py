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
        self.sock.settimeout(30.0)  # 30 second timeout
        print(f"[+] Connected to server at {self.server_host}:{self.server_port}")

    def send_hello(self):
        payload = b"HELLO"
        enc_key, mac_key = self.session.c2s_enc_key, self.session.c2s_mac_key

        header = struct.pack(
            '!B B I B',
            Opcode.CLIENT_HELLO,
            self.client_id,
            self.session.round_number,
            Direction.CLIENT_TO_SERVER
        )

        iv, ciphertext, hmac_tag = encrypt_and_authenticate(
            payload, enc_key, mac_key, header
        )

        msg = pack_message(
            Opcode.CLIENT_HELLO,
            self.client_id,
            self.session.round_number,
            Direction.CLIENT_TO_SERVER,
            iv,
            ciphertext,
            hmac_tag
        )

        self.sock.sendall(msg)
        print(f"[+] Sent CLIENT_HELLO (Round {self.session.round_number})")
        
        # evolve keys after sending
        self.session.evolve_recv_keys(ciphertext, iv)

    def receive_challenge(self):
        data = self.sock.recv(4096)
        if not data:
            print("[!] No data received")
            return None

        msg = unpack_message(data)
        if msg is None:
            print("[!] Invalid message")
            return None

        if msg['opcode'] != Opcode.SERVER_CHALLENGE:
            print("[!] Unexpected opcode")
            return None

        if msg['round'] != self.session.round_number:
            print("[!] Round mismatch")
            return None

        enc_key, mac_key = self.session.s2c_enc_key, self.session.s2c_mac_key

        plaintext = verify_and_decrypt(
            msg['ciphertext'],
            enc_key,
            mac_key,
            msg['header'],
            msg['hmac'],
            msg['iv']
        )

        if plaintext is None:
            print("[!] HMAC verification failed")
            return None

        print(f"[+] Received SERVER_CHALLENGE (Round {self.session.round_number})")
        
        # evolve keys after receiving
        self.session.evolve_send_keys(msg['ciphertext'], plaintext)
        
        transition_state(self.session, ProtocolState.ACTIVE)
        advance_round(self.session)
        
        return plaintext

    def send_data(self, value):
        payload = struct.pack('!I', value)
        enc_key, mac_key = self.session.c2s_enc_key, self.session.c2s_mac_key

        header = struct.pack(
            '!B B I B',
            Opcode.CLIENT_DATA,
            self.client_id,
            self.session.round_number,
            Direction.CLIENT_TO_SERVER
        )

        iv, ciphertext, hmac_tag = encrypt_and_authenticate(
            payload, enc_key, mac_key, header
        )

        msg = pack_message(
            Opcode.CLIENT_DATA,
            self.client_id,
            self.session.round_number,
            Direction.CLIENT_TO_SERVER,
            iv,
            ciphertext,
            hmac_tag
        )

        self.sock.sendall(msg)
        print(f"[+] Sent CLIENT_DATA: {value} (Round {self.session.round_number})")

        # evolve keys after sending
        self.session.evolve_recv_keys(ciphertext, iv)

    def receive_aggregation(self):
        try:
            data = self.sock.recv(4096)
        except socket.timeout:
            print("[!] Timeout waiting for aggregation")
            return None
        except Exception as e:
            print(f"[!] Error receiving aggregation: {e}")
            return None
            
        if not data:
            print("[!] No data received (connection closed)")
            return None

        msg = unpack_message(data)
        if msg is None:
            print("[!] Invalid message")
            return None

        if msg['opcode'] != Opcode.SERVER_AGGR_RESPONSE:
            print(f"[!] Unexpected opcode: {msg['opcode']}")
            return None

        if msg['round'] != self.session.round_number:
            print(f"[!] Round mismatch: expected {self.session.round_number}, got {msg['round']}")
            return None

        enc_key, mac_key = self.session.s2c_enc_key, self.session.s2c_mac_key

        plaintext = verify_and_decrypt(
            msg['ciphertext'],
            enc_key,
            mac_key,
            msg['header'],
            msg['hmac'],
            msg['iv']
        )

        if plaintext is None:
            print("[!] HMAC verification failed")
            return None

        agg_value = struct.unpack('!I', plaintext)[0]
        print(f"[+] Received aggregation: {agg_value} (Round {msg['round']})")

        # evolve keys after receiving
        self.session.evolve_send_keys(msg['ciphertext'], plaintext)

        # advance to next round
        advance_round(self.session)
        
        return agg_value

    def run_single(self, value):
        """Run single data exchange and exit"""
        try:
            self.connect()
            self.send_hello()

            if self.receive_challenge() is None:
                return

            self.send_data(value)

            if self.receive_aggregation() is None:
                return

            print("[+] Protocol completed successfully")

        finally:
            if self.sock:
                self.sock.close()

    def run_interactive(self):
        """Run interactive mode - multiple data exchanges in one session"""
        try:
            # initial handshake
            self.connect()
            self.send_hello()

            if self.receive_challenge() is None:
                print("[!] Handshake failed")
                return

            print("\n[+] Handshake complete, now in ACTIVE state")
            print("[*] Enter values to send (or 'q' to quit)")
            
            # interactive loop for multiple rounds
            while True:
                try:
                    user_input = input(f"\nRound {self.session.round_number} > ")
                    
                    if user_input.lower() in ['q', 'quit', 'exit']:
                        print("[*] Closing connection")
                        break
                    
                    try:
                        value = int(user_input)
                    except ValueError:
                        print("[!] Please enter a valid number or 'q' to quit")
                        continue
                    
                    # send data for this round
                    self.send_data(value)
                    
                    # receive aggregation
                    agg = self.receive_aggregation()
                    if agg is None:
                        print("[!] Protocol error, closing")
                        break
                    
                    print(f"[+] Current round: {self.session.round_number}")
                    
                except KeyboardInterrupt:
                    print("\n[*] Interrupted by user")
                    break

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

    client_id = int(sys.argv[1])
    master_key = bytes.fromhex(sys.argv[2])
    
    client = SecureClient(client_id, master_key)
    
    # check if interactive mode
    if len(sys.argv) > 3 and sys.argv[3] == '-i':
        client.run_interactive()
    else:
        value = int(sys.argv[3]) if len(sys.argv) > 3 else 100
        client.run_single(value)