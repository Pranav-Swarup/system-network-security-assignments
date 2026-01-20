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
    encrypt_and_authenticate, verify_and_decrypt, generate_iv
)


class SecureServer:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.sessions = {}  # client_id -> ClientSession
        self.lock = threading.Lock()
        self.round_data = {}  # round_num -> [data1, data2, ...]
        
        # Pre-shared master keys for clients (in practice, securely provisioned)
        self.master_keys = {
            1: os.urandom(16),
            2: os.urandom(16),
            3: os.urandom(16),
        }
    
    def get_master_key(self, client_id):
        """Retrieve master key for client."""
        return self.master_keys.get(client_id)
    
    def handle_client_hello(self, session, msg_data):
        """
        Handle CLIENT_HELLO opcode.
        Send SERVER_CHALLENGE in response.
        """
        # CLIENT_HELLO has no encrypted payload (just hello)
        print(f"[+] Client {session.client_id} initiated protocol")
        
        # Generate challenge nonce
        challenge_nonce = os.urandom(16)
        
        # Encrypt challenge
        enc_key, mac_key = session.get_send_keys()
        
        # Build header WITHOUT IV
        header_data = struct.pack('!B B I B', 
                                  Opcode.SERVER_CHALLENGE,
                                  session.client_id,
                                  session.round_number,
                                  Direction.SERVER_TO_CLIENT)
        
        # Encrypt and authenticate (IV generated inside)
        iv, ciphertext, hmac_tag = encrypt_and_authenticate(
            challenge_nonce, enc_key, mac_key, header_data
        )
        
        # Pack and return message
        response = pack_message(
            Opcode.SERVER_CHALLENGE,
            session.client_id,
            session.round_number,
            Direction.SERVER_TO_CLIENT,
            iv,
            ciphertext,
            hmac_tag
        )
        
        # Evolve keys after sending
        session.evolve_send_keys(ciphertext, struct.pack('!B', 1))
        
        # Transition to ACTIVE state
        transition_state(session, ProtocolState.ACTIVE)
        
        return response, challenge_nonce
    
    def handle_client_data(self, session, msg_data, iv):
        """
        Handle CLIENT_DATA opcode.
        Decrypt data and store for aggregation.
        """
        enc_key, mac_key = session.get_recv_keys()
        
        # Verify and decrypt
        plaintext = verify_and_decrypt(
            msg_data['ciphertext'],
            enc_key,
            mac_key,
            msg_data['header'],
            msg_data['hmac'],
            iv
        )
        
        if plaintext is None:
            print(f"[!] HMAC verification failed for client {session.client_id}")
            session.terminate()
            return None
        
        # Parse numeric data (4-byte integer)
        if len(plaintext) < 4:
            print(f"[!] Invalid data format from client {session.client_id}")
            session.terminate()
            return None
        
        client_value = struct.unpack('!I', plaintext[:4])[0]
        print(f"[+] Received data from client {session.client_id}: {client_value}")
        
        # Store data for this round
        round_num = msg_data['round']
        with self.lock:
            if round_num not in self.round_data:
                self.round_data[round_num] = []
            self.round_data[round_num].append(client_value)
        
        # Evolve keys after successful verification
        session.evolve_recv_keys(msg_data['ciphertext'], iv)
        
        return client_value
    
    def compute_aggregation(self, round_num):
        """Compute sum of all data for given round."""
        with self.lock:
            if round_num in self.round_data:
                return sum(self.round_data[round_num])
            return 0
    
    def send_aggregation(self, session, aggregated_value, conn):
        """
        Send SERVER_AGGR_RESPONSE with aggregated result.
        """
        # Pack aggregated value
        payload = struct.pack('!I', aggregated_value)
        
        # Encrypt payload
        enc_key, mac_key = session.get_send_keys()
        
        # Build header WITHOUT IV
        header_data = struct.pack('!B B I B',
                                  Opcode.SERVER_AGGR_RESPONSE,
                                  session.client_id,
                                  session.round_number,
                                  Direction.SERVER_TO_CLIENT)
        
        # Encrypt and authenticate (IV generated inside)
        iv, ciphertext, hmac_tag = encrypt_and_authenticate(
            payload, enc_key, mac_key, header_data
        )
        
        # Pack message
        response = pack_message(
            Opcode.SERVER_AGGR_RESPONSE,
            session.client_id,
            session.round_number,
            Direction.SERVER_TO_CLIENT,
            iv,
            ciphertext,
            hmac_tag
        )
        
        # Evolve keys after sending
        session.evolve_send_keys(ciphertext, struct.pack('!I', aggregated_value))
        
        # Send response
        conn.sendall(response)
        print(f"[+] Sent aggregated result to client {session.client_id}: {aggregated_value}")
    
    def handle_connection(self, conn, addr):
        """Handle individual client connection."""
        print(f"[*] Connection from {addr}")
        
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
            
            # Get or create session
            with self.lock:
                if client_id not in self.sessions:
                    master_key = self.get_master_key(client_id)
                    if master_key is None:
                        print(f"[!] Unknown client ID: {client_id}")
                        return
                    self.sessions[client_id] = ClientSession(client_id, master_key)
                
                session = self.sessions[client_id]
            
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
                conn.sendall(response)
            
            # Advance round after HELLO exchange
            advance_round(session)
            
            # Receive CLIENT_DATA
            data = conn.recv(4096)
            if not data:
                return
            
            msg_data = unpack_message(data)
            if msg_data is None:
                print("[!] Invalid message format")
                session.terminate()
                return
            
            # Validate state
            if not validate_message_state(session, msg_data['opcode'],
                                         msg_data['round'], msg_data['direction'],
                                         Direction.CLIENT_TO_SERVER):
                print(f"[!] State validation failed for client {client_id}")
                session.terminate()
                return
            
            # Handle CLIENT_DATA
            if msg_data['opcode'] == Opcode.CLIENT_DATA:
                client_value = self.handle_client_data(session, msg_data, msg_data['iv'])
                
                if client_value is None:
                    return
                
                # Compute and send aggregation
                agg_value = self.compute_aggregation(msg_data['round'])
                self.send_aggregation(session, agg_value, conn)
        
        except Exception as e:
            print(f"[!] Error handling client: {e}")
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
                client_thread.start()
            except KeyboardInterrupt:
                print("\n[*] Server shutting down")
                break
        
        server_socket.close()


if __name__ == "__main__":
    server = SecureServer()
    
    # Print master keys for testing (NEVER do this in production!)
    print("[*] Master keys for testing:")
    for cid, key in server.master_keys.items():
        print(f"  Client {cid}: {key.hex()}")
    
    server.start()