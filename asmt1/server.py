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
        
        self.master_keys = {
            1: os.urandom(16),
            2: os.urandom(16),
            3: os.urandom(16),
        }
    
    def get_master_key(self, client_id):
        return self.master_keys.get(client_id)
    
    def send_error_response(self, conn, client_id, round_num, error_type="GENERIC"):
        """Send an error response to the client before terminating"""
        try:
            # Use a simple error message format - no encryption needed for error
            # since we're terminating anyway
            error_payload = error_type.encode('utf-8')
            
            # Pack a KEY_DESYNC_ERROR or TERMINATE message
            header = struct.pack('!B B I B',
                                Opcode.KEY_DESYNC_ERROR,
                                client_id,
                                round_num,
                                Direction.SERVER_TO_CLIENT)
            
            # Send minimal error response (header + error message)
            # Using zeros for IV and HMAC since this is a termination signal
            iv = b'\x00' * 16
            hmac_tag = b'\x00' * 32
            
            response = header + iv + error_payload + hmac_tag
            conn.sendall(response)
            print(f"[!] Sent error response to client {client_id}: {error_type}")
        except Exception as e:
            print(f"[!] Failed to send error response: {e}")
    
    def handle_client_hello(self, session, msg_data, conn):
        """Handle CLIENT_HELLO - stays at Round 0"""
        print(f"[+] Client {session.client_id} initiated protocol")
        
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
            self.send_error_response(conn, session.client_id, session.round_number, "HMAC_FAILED")
            session.terminate()
            return None, None
        
        # evolve C2S keys
        session.evolve_recv_keys(msg_data['ciphertext'], msg_data['iv'])
        
        challenge_nonce = os.urandom(16)
        
        enc_key, mac_key = session.get_send_keys()
        
        header_data = struct.pack('!B B I B', 
                                  Opcode.SERVER_CHALLENGE,
                                  session.client_id,
                                  session.round_number,
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
        
        # evolve S2C keys
        session.evolve_send_keys(ciphertext, challenge_nonce)
        
        transition_state(session, ProtocolState.ACTIVE)
        advance_round(session)
        
        return response, challenge_nonce
    
    def handle_client_data(self, session, msg_data, conn):
        """Handle CLIENT_DATA"""
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
            self.send_error_response(conn, session.client_id, session.round_number, "HMAC_FAILED")
            session.terminate()
            return None
        
        if len(plaintext) < 4:
            print(f"[!] Invalid data format from client {session.client_id}")
            self.send_error_response(conn, session.client_id, session.round_number, "INVALID_FORMAT")
            session.terminate()
            return None
        
        client_value = struct.unpack('!I', plaintext[:4])[0]
        print(f"[+] Received data from client {session.client_id}: {client_value} (Round {msg_data['round']})")
        
        round_num = msg_data['round']
        with self.lock:
            if round_num not in self.round_data:
                self.round_data[round_num] = {}
            self.round_data[round_num][session.client_id] = client_value
        
        # evolve C2S keys
        session.evolve_recv_keys(msg_data['ciphertext'], msg_data['iv'])
        
        return client_value
    
    def compute_aggregation(self, round_num):
        """Compute sum of all data for given round"""
        with self.lock:
            if round_num in self.round_data:
                return sum(self.round_data[round_num].values())
            return 0
    
    def send_aggregation(self, session, aggregated_value, conn):
        """Send SERVER_AGGR_RESPONSE"""
        payload = struct.pack('!I', aggregated_value)
        
        enc_key, mac_key = session.get_send_keys()
        
        header_data = struct.pack('!B B I B',
                                  Opcode.SERVER_AGGR_RESPONSE,
                                  session.client_id,
                                  session.round_number,
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
        
        # evolve S2C keys
        session.evolve_send_keys(ciphertext, payload)
        
        conn.sendall(response)
        print(f"[+] Sent aggregated result to client {session.client_id}: {aggregated_value} (Round {session.round_number})")
        
        # advance to next round
        advance_round(session)
    
    def handle_connection(self, conn, addr):
        """Handle individual client connection with multiple rounds"""
        print(f"[*] Connection from {addr}")
        session = None
        client_id = None
        
        # set socket timeout to detect dead connections
        conn.settimeout(30.0)
        
        try:
            # receive CLIENT_HELLO
            data = conn.recv(4096)
            if not data:
                print("[!] No data received")
                return
            
            msg_data = unpack_message(data)
            if msg_data is None:
                print("[!] Invalid message format - malformed packet")
                # Can't send proper error without client_id, just close
                return
            
            client_id = msg_data['client_id']
            
            # Check if client is known
            master_key = self.get_master_key(client_id)
            if master_key is None:
                print(f"[!] Unknown client ID: {client_id}")
                self.send_error_response(conn, client_id, 0, "UNKNOWN_CLIENT")
                return
            
            # Create fresh session per connection
            session = ClientSession(client_id, master_key)
            
            # Validate message state BEFORE processing
            if not validate_message_state(session, msg_data['opcode'], 
                                         msg_data['round'], msg_data['direction'],
                                         Direction.CLIENT_TO_SERVER):
                print(f"[!] Invalid message state for client {client_id}")
                print(f"    Expected: opcode={Opcode.CLIENT_HELLO}, round={session.round_number}, state={session.state}")
                print(f"    Received: opcode={msg_data['opcode']}, round={msg_data['round']}")
                self.send_error_response(conn, client_id, msg_data['round'], "STATE_VIOLATION")
                session.terminate()
                return
            
            # handle HELLO
            if msg_data['opcode'] == Opcode.CLIENT_HELLO:
                response, nonce = self.handle_client_hello(session, msg_data, conn)
                if response is None:
                    # Error already sent in handle_client_hello
                    return
                conn.sendall(response)
            
            # now handle multiple data rounds
            while not session.is_terminated():
                try:
                    data = conn.recv(4096)
                    if not data:
                        print(f"[*] Client {client_id} disconnected")
                        break
                except socket.timeout:
                    print(f"[*] Client {client_id} connection timeout")
                    break
                except Exception as e:
                    print(f"[!] Error receiving data: {e}")
                    break
                
                msg_data = unpack_message(data)
                if msg_data is None:
                    print("[!] Invalid message format")
                    self.send_error_response(conn, client_id, session.round_number, "MALFORMED_MESSAGE")
                    session.terminate()
                    break
                
                # Validate state BEFORE processing
                if not validate_message_state(session, msg_data['opcode'],
                                             msg_data['round'], msg_data['direction'],
                                             Direction.CLIENT_TO_SERVER):
                    print(f"[!] State validation failed for client {client_id}")
                    print(f"    Expected: round={session.round_number}, state={session.state}")
                    print(f"    Received: opcode={msg_data['opcode']}, round={msg_data['round']}")
                    
                    # Determine specific error type
                    if msg_data['round'] != session.round_number:
                        error_type = "ROUND_MISMATCH"
                    elif msg_data['direction'] != Direction.CLIENT_TO_SERVER:
                        error_type = "DIRECTION_ERROR"
                    else:
                        error_type = "INVALID_OPCODE"
                    
                    self.send_error_response(conn, client_id, session.round_number, error_type)
                    session.terminate()
                    break
                
                # handle CLIENT_DATA
                if msg_data['opcode'] == Opcode.CLIENT_DATA:
                    client_value = self.handle_client_data(session, msg_data, conn)
                    
                    if client_value is None:
                        # Error already sent in handle_client_data
                        break
                    
                    # compute and send aggregation
                    agg_value = self.compute_aggregation(msg_data['round'])
                    self.send_aggregation(session, agg_value, conn)
                
                elif msg_data['opcode'] == Opcode.TERMINATE:
                    print(f"[*] Client {client_id} requested termination")
                    session.terminate()
                    break
        
        except Exception as e:
            print(f"[!] Error handling connection: {e}")
            if session and client_id:
                self.send_error_response(conn, client_id, session.round_number if session else 0, "SERVER_ERROR")
                session.terminate()
        finally:
            conn.close()
            print(f"[*] Connection closed for client {client_id if client_id else 'unknown'}")
    
    def start(self):
        """Start the server"""
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