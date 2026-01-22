import socket
import threading
import struct
import os
from protocol_fsm import (
    ClientSession, ProtocolState, Opcode, Direction,
    pack_message, unpack_message, validate_message_state,
    advance_round, transition_state
)
from crypto_utils import (
    encrypt_and_authenticate, verify_and_decrypt
)


class SecureServer:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.lock = threading.Lock()
        self.round_data = {}  # round_num -> {client_id: value}
        
        # Pre-shared master keys for clients
        self.master_keys = {
            1: os.urandom(16),
            2: os.urandom(16),
            3: os.urandom(16),
        }
    
    def get_master_key(self, client_id):
        return self.master_keys.get(client_id)
    
    def handle_client_hello(self, session, msg_data):
        """
        Handle CLIENT_HELLO - verify, send challenge, evolve keys.
        Round stays at 0 for both HELLO and CHALLENGE.
        """
        print(f"[+] Client {session.client_id} initiated protocol")
        
        # Verify and decrypt CLIENT_HELLO
        enc_key, mac_key = session.get_recv_keys()
        
        plaintext = verify_and_decrypt(
            msg_data['ciphertext'],
            enc_key,
            mac_key,
            msg_data['header'],
            msg_data['hmac'],
            msg_data['iv']
        )
        
        if plaintext is None:
            print(f"[!] HMAC verification failed for CLIENT_HELLO")
            session.terminate()
            return None, None
        
        # Evolve C2S keys after receiving HELLO
        session.evolve_recv_keys(msg_data['ciphertext'], msg_data['iv'])
        
        # Generate challenge nonce
        challenge_nonce = os.urandom(16)
        
        # Send SERVER_CHALLENGE (still Round 0)
        enc_key, mac_key = session.get_send_keys()
        
        header_data = struct.pack('!B B I B', 
                                  Opcode.SERVER_CHALLENGE,
                                  session.client_id,
                                  session.round_number,  # Still 0
                                  Direction.SERVER_TO_CLIENT)
        
        iv, ciphertext, hmac_tag = encrypt_and_authenticate(
            challenge_nonce, enc_key, mac_key, header_data
        )
        
        response = pack_message(
            Opcode.SERVER_CHALLENGE,
            session.client_id,
            session.round_number,
            Direction.SERVER_TO_CLIENT,
            iv,
            ciphertext,
            hmac_tag
        )
        
        # Evolve S2C keys after sending CHALLENGE
        # Use ciphertext and the actual nonce payload
        session.evolve_send_keys(ciphertext, challenge_nonce)
        
        # Transition to ACTIVE
        transition_state(session, ProtocolState.ACTIVE)
        
        # Advance to Round 1 after complete HELLO/CHALLENGE exchange
        advance_round(session)
        
        return response, challenge_nonce
    
    def handle_client_data(self, session, msg_data):
        """
        Handle CLIENT_DATA - verify, store for aggregation, evolve keys.
        """
        enc_key, mac_key = session.get_recv_keys()
        
        plaintext = verify_and_decrypt(
            msg_data['ciphertext'],
            enc_key,
            mac_key,
            msg_data['header'],
            msg_data['hmac'],
            msg_data['iv']
        )
        
        if plaintext is None:
            print(f"[!] HMAC verification failed for client {session.client_id}")
            session.terminate()
            return None
        
        if len(plaintext) < 4:
            print(f"[!] Invalid data format from client {session.client_id}")
            session.terminate()
            return None
        
        client_value = struct.unpack('!I', plaintext[:4])[0]
        print(f"[+] Received data from client {session.client_id}: {client_value}")
        
        # Store for aggregation
        round_num = msg_data['round']
        with self.lock:
            if round_num not in self.round_data:
                self.round_data[round_num] = {}
            self.round_data[round_num][session.client_id] = client_value
        
        # Evolve C2S keys after successful receipt
        session.evolve_recv_keys(msg_data['ciphertext'], msg_data['iv'])
        
        return client_value
    
    def compute_aggregation(self, round_num):
        """Compute sum of all data for given round."""
        with self.lock:
            if round_num in self.round_data:
                return sum(self.round_data[round_num].values())
            return 0
    
    def send_aggregation(self, session, aggregated_value, conn):
        """
        Send SERVER_AGGR_RESPONSE (still at current round).
        """
        # Pack aggregated value
        payload = struct.pack('!I', aggregated_value)
        
        enc_key, mac_key = session.get_send_keys()
        
        header_data = struct.pack('!B B I B',
                                  Opcode.SERVER_AGGR_RESPONSE,
                                  session.client_id,
                                  session.round_number,  # Same round as DATA
                                  Direction.SERVER_TO_CLIENT)
        
        iv, ciphertext, hmac_tag = encrypt_and_authenticate(
            payload, enc_key, mac_key, header_data
        )
        
        response = pack_message(
            Opcode.SERVER_AGGR_RESPONSE,
            session.client_id,
            session.round_number,
            Direction.SERVER_TO_CLIENT,
            iv,
            ciphertext,
            hmac_tag
        )
        
        # Evolve S2C keys after sending
        # Use ciphertext and the actual aggregated data payload
        session.evolve_send_keys(ciphertext, payload)
        
        conn.sendall(response)
        print(f"[+] Sent aggregated result to client {session.client_id}: {aggregated_value}")
        
        # Advance to next round after complete DATA/AGGR exchange
        advance_round(session)
    
    def handle_connection(self, conn, addr):
        """Handle individual client connection."""
        print(f"[*] Connection from {addr}")
        session = None
        
        try:
            # Receive CLIENT_HELLO
            data = conn.recv(4096)
            if not data:
                return
            
            msg_data = unpack_message(data)
            if msg_data is None:
                print("[!] Invalid message format")
                return
            
            client_id = msg_data['client_id']
            
            # CRITICAL FIX: Always create fresh session per connection
            master_key = self.get_master_key(client_id)
            if master_key is None:
                print(f"[!] Unknown client ID: {client_id}")
                return
            
            session = ClientSession(client_id, master_key)
            
            # Validate message state
            if not validate_message_state(session, msg_data['opcode'], 
                                         msg_data['round'], msg_data['direction'],
                                         Direction.CLIENT_TO_SERVER):
                print(f"[!] Invalid message state for client {client_id}")
                session.terminate()
                return
            
            # Handle CLIENT_HELLO
            if msg_data['opcode'] == Opcode.CLIENT_HELLO:
                response, nonce = self.handle_client_hello(session, msg_data)
                if response is None:
                    return
                conn.sendall(response)
            
            # Now at Round 1 - receive CLIENT_DATA
            data = conn.recv(4096)
            if not data:
                return
            
            msg_data = unpack_message(data)
            if msg_data is None:
                print("[!] Invalid message format")
                session.terminate()
                return
            
            # Validate state for CLIENT_DATA
            if not validate_message_state(session, msg_data['opcode'],
                                         msg_data['round'], msg_data['direction'],
                                         Direction.CLIENT_TO_SERVER):
                print(f"[!] State validation failed for client {client_id}")
                session.terminate()
                return
            
            # Handle CLIENT_DATA
            if msg_data['opcode'] == Opcode.CLIENT_DATA:
                client_value = self.handle_client_data(session, msg_data)
                
                if client_value is None:
                    return
                
                # Compute aggregation
                agg_value = self.compute_aggregation(msg_data['round'])
                
                # Send aggregation
                self.send_aggregation(session, agg_value, conn)
        
        except Exception as e:
            print(f"[!] Error: {e}")
            if session:
                session.terminate()
        finally:
            conn.close()
    
    def start(self):
        """Start the server."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"[*] Server listening on {self.host}:{self.port}")
        
        while True:
            try:
                conn, addr = server_socket.accept()
                client_thread = threading.Thread(target=self.handle_connection, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
            except KeyboardInterrupt:
                print("\n[*] Server shutting down")
                break
        
        server_socket.close()


if __name__ == "__main__":
    server = SecureServer()
    
    print("[*] Master keys for testing:")
    for cid, key in server.master_keys.items():
        print(f"  Client {cid}: {key.hex()}")
    
    server.start()