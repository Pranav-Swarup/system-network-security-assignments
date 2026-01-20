import socket
import struct
import os
from protocol_fsm import (
    ClientSession, ProtocolState, Opcode, Direction,
    pack_message, unpack_message, advance_round, transition_state
)
from crypto_utils import (
    encrypt_and_authenticate, verify_and_decrypt, generate_iv
)


class SecureClient:
    def __init__(self, client_id, master_key, server_host='127.0.0.1', server_port=9999):
        self.client_id = client_id
        self.session = ClientSession(client_id, master_key)
        self.server_host = server_host
        self.server_port = server_port
        self.sock = None
    
    def connect(self):
        """Connect to server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_host, self.server_port))
        print(f"[+] Connected to server at {self.server_host}:{self.server_port}")
    
    def send_hello(self):
        """Send CLIENT_HELLO to initiate protocol."""
        # CLIENT_HELLO has minimal payload
        payload = b"HELLO"
        
        # Get keys for sending
        enc_key, mac_key = self.session.c2s_enc_key, self.session.c2s_mac_key
        
        # Build header
        header_data = struct.pack('!B B I B',
                                  Opcode.CLIENT_HELLO,
                                  self.client_id,
                                  self.session.round_number,
                                  Direction.CLIENT_TO_SERVER)
        
        iv = generate_iv()
        iv_with_header = header_data + iv
        
        # Encrypt and authenticate
        iv, ciphertext, hmac_tag = encrypt_and_authenticate(
            payload, enc_key, mac_key, iv_with_header
        )
        
        # Pack message
        message = pack_message(
            Opcode.CLIENT_HELLO,
            self.client_id,
            self.session.round_number,
            Direction.CLIENT_TO_SERVER,
            iv,
            ciphertext,
            hmac_tag
        )
        
        # Send message
        self.sock.sendall(message)
        print(f"[+] Sent CLIENT_HELLO (Round {self.session.round_number})")
        
        # Evolve keys after sending
        self.session.c2s_enc_key = self.session.c2s_enc_key  # Will be evolved by key ratchet
        self.session.c2s_mac_key = self.session.c2s_mac_key
    
    def receive_challenge(self):
        """Receive and verify SERVER_CHALLENGE."""
        data = self.sock.recv(4096)
        
        if not data:
            print("[!] No data received")
            return None
        
        # Unpack message
        msg_data = unpack_message(data)
        if msg_data is None:
            print("[!] Invalid message format")
            self.session.terminate()
            return None
        
        # Verify this is SERVER_CHALLENGE
        if msg_data['opcode'] != Opcode.SERVER_CHALLENGE:
            print("[!] Unexpected opcode")
            self.session.terminate()
            return None
        
        # Verify round number
        if msg_data['round'] != self.session.round_number:
            print(f"[!] Round mismatch: expected {self.session.round_number}, got {msg_data['round']}")
            self.session.terminate()
            return None
        
        # Verify direction
        if msg_data['direction'] != Direction.SERVER_TO_CLIENT:
            print("[!] Wrong direction")
            self.session.terminate()
            return None
        
        # Get keys for receiving
        enc_key, mac_key = self.session.s2c_enc_key, self.session.s2c_mac_key
        
        # Verify and decrypt
        plaintext = verify_and_decrypt(
            msg_data['ciphertext'],
            enc_key,
            mac_key,
            msg_data['header'],
            msg_data['hmac'],
            msg_data['iv']
        )
        
        if plaintext is None:
            print("[!] HMAC verification failed")
            self.session.terminate()
            return None
        
        print(f"[+] Received SERVER_CHALLENGE (Round {self.session.round_number})")
        
        # Evolve S2C keys after successful verification
        self.session.s2c_enc_key = self.session.s2c_enc_key  # Evolved separately
        
        # Transition to ACTIVE
        transition_state(self.session, ProtocolState.ACTIVE)
        
        return plaintext
    
    def send_data(self, numeric_value):
        """Send CLIENT_DATA with numeric value."""
        # Increment round for data exchange
        advance_round(self.session)
        
        # Pack numeric value (4 bytes)
        payload = struct.pack('!I', numeric_value)
        
        # Get keys
        enc_key, mac_key = self.session.c2s_enc_key, self.session.c2s_mac_key
        
        # Build header
        header_data = struct.pack('!B B I B',
                                  Opcode.CLIENT_DATA,
                                  self.client_id,
                                  self.session.round_number,
                                  Direction.CLIENT_TO_SERVER)
        
        iv = generate_iv()
        iv_with_header = header_data + iv
        
        # Encrypt and authenticate
        iv, ciphertext, hmac_tag = encrypt_and_authenticate(
            payload, enc_key, mac_key, iv_with_header
        )
        
        # Pack message
        message = pack_message(
            Opcode.CLIENT_DATA,
            self.client_id,
            self.session.round_number,
            Direction.CLIENT_TO_SERVER,
            iv,
            ciphertext,
            hmac_tag
        )
        
        # Send message
        self.sock.sendall(message)
        print(f"[+] Sent CLIENT_DATA: {numeric_value} (Round {self.session.round_number})")
        
        # Evolve C2S keys after sending
        self.session.c2s_enc_key = self.session.c2s_enc_key  # Store for evolution
        self.session.evolve_recv_keys(ciphertext, iv)  # Use helper method
    
    def receive_aggregation(self):
        """Receive SERVER_AGGR_RESPONSE with aggregated result."""
        data = self.sock.recv(4096)
        
        if not data:
            print("[!] No data received")
            return None
        
        # Unpack message
        msg_data = unpack_message(data)
        if msg_data is None:
            print("[!] Invalid message format")
            self.session.terminate()
            return None
        
        # Verify opcode
        if msg_data['opcode'] != Opcode.SERVER_AGGR_RESPONSE:
            print("[!] Unexpected opcode")
            self.session.terminate()
            return None
        
        # Verify round number (should be incremented)
        expected_round = self.session.round_number + 1
        if msg_data['round'] != expected_round:
            print(f"[!] Round mismatch: expected {expected_round}, got {msg_data['round']}")
            self.session.terminate()
            return None
        
        # Get keys
        enc_key, mac_key = self.session.s2c_enc_key, self.session.s2c_mac_key
        
        # Verify and decrypt
        plaintext = verify_and_decrypt(
            msg_data['ciphertext'],
            enc_key,
            mac_key,
            msg_data['header'],
            msg_data['hmac'],
            msg_data['iv']
        )
        
        if plaintext is None:
            print("[!] HMAC verification failed")
            self.session.terminate()
            return None
        
        # Parse aggregated value
        if len(plaintext) < 4:
            print("[!] Invalid aggregation format")
            self.session.terminate()
            return None
        
        agg_value = struct.unpack('!I', plaintext[:4])[0]
        print(f"[+] Received aggregation: {agg_value} (Round {msg_data['round']})")
        
        # Update round number
        self.session.round_number = msg_data['round']
        
        return agg_value
    
    def run(self, data_value):
        """Run complete protocol exchange."""
        try:
            # Step 1: Connect
            self.connect()
            
            # Step 2: Send HELLO
            self.send_hello()
            
            # Step 3: Receive CHALLENGE
            challenge = self.receive_challenge()
            if challenge is None:
                print("[!] Protocol failed at CHALLENGE")
                return
            
            # Step 4: Send DATA
            self.send_data(data_value)
            
            # Step 5: Receive AGGREGATION
            result = self.receive_aggregation()
            if result is None:
                print("[!] Protocol failed at AGGREGATION")
                return
            
            print(f"[+] Protocol completed successfully!")
            print(f"[+] Final aggregated value: {result}")
        
        except Exception as e:
            print(f"[!] Error during protocol: {e}")
        finally:
            if self.sock:
                self.sock.close()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python client.py <client_id> <master_key_hex> [data_value]")
        print("Example: python client.py 1 0123456789abcdef0123456789abcdef 42")
        sys.exit(1)
    
    client_id = int(sys.argv[1])
    master_key = bytes.fromhex(sys.argv[2])
    data_value = int(sys.argv[3]) if len(sys.argv) > 3 else 100
    
    client = SecureClient(client_id, master_key)
    client.run(data_value)