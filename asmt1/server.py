import socket
import threading
import struct
import os
import logging
from datetime import datetime
from protocol_fsm import (
    ClientSession, ProtocolState, Opcode, Direction,
    pack_message, unpack_message, validate_message_state,
    advance_round, transition_state
)
from crypto_utils import (
    encrypt_and_authenticate, verify_and_decrypt, generate_iv
)

# Setup proper logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d [%(levelname)s] [%(threadName)-10s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Separate security logger for attacks
security_logger = logging.getLogger('security')
security_handler = logging.FileHandler('security_events.log')
security_handler.setFormatter(
    logging.Formatter('%(asctime)s [SECURITY] %(message)s')
)
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.WARNING)


def log_security_event(event_type, client_id, details, severity="WARNING"):
    """Log security events separately"""
    msg = f"[{severity}] {event_type} | Client: {client_id} | {details}"
    security_logger.warning(msg)
    logging.warning(msg)


def hex_dump(data, max_bytes=32):
    """Return hex representation of data"""
    preview = data[:max_bytes]
    hex_str = preview.hex()
    suffix = "..." if len(data) > max_bytes else ""
    return f"{hex_str}{suffix} ({len(data)} bytes)"


class SecureServer:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.sessions = {}
        self.lock = threading.Lock()
        self.round_data = {}
        self.connection_counter = 0
        
        self.master_keys = {
            1: os.urandom(16),
            2: os.urandom(16),
            3: os.urandom(16),
        }
        
        logging.info("="*60)
        logging.info("Secure Server Initialized")
        logging.info("="*60)
        logging.info("Master keys for testing:")
        for cid, key in self.master_keys.items():
            logging.info(f"  Client {cid}: {key.hex()}")
    
    def get_master_key(self, client_id):
        return self.master_keys.get(client_id)
    
    def handle_client_hello(self, session, msg_data, conn_id):
        """
        Handle CLIENT_HELLO with HMAC verification.
        Returns (response, nonce) on success, (None, None) on failure.
        
        IMPORTANT: Client does NOT evolve keys after sending CLIENT_HELLO,
        so server must NOT evolve C2S keys after receiving it.
        """
        logging.info(f"[Conn-{conn_id}] Processing CLIENT_HELLO from client {session.client_id}")
        
        # STEP 1: VERIFY HMAC ON INCOMING CLIENT_HELLO using initial C2S keys
        enc_key, mac_key = session.get_recv_keys()  # Initial C2S keys
        
        plaintext = verify_and_decrypt(
            msg_data['ciphertext'],
            enc_key,
            mac_key,
            msg_data['header'],
            msg_data['hmac'],
            msg_data['iv']
        )
        
        if plaintext is None:
            log_security_event(
                "HMAC_VERIFICATION_FAILED_ON_HELLO",
                session.client_id,
                f"Round: {msg_data['round']}, Conn: {conn_id}, "
                f"Ciphertext: {hex_dump(msg_data['ciphertext'], 16)}, "
                f"HMAC: {hex_dump(msg_data['hmac'], 16)}",
                "CRITICAL"
            )
            session.terminate()
            return None, None
        
        # Verify payload is "HELLO"
        if plaintext != b"HELLO":
            log_security_event(
                "INVALID_HELLO_PAYLOAD",
                session.client_id,
                f"Expected b'HELLO', got {plaintext[:20]}, Conn: {conn_id}",
                "HIGH"
            )
            session.terminate()
            return None, None
        
        logging.info(f"[Conn-{conn_id}] CLIENT_HELLO HMAC verified successfully")
        
        # DO NOT EVOLVE C2S KEYS HERE - client doesn't evolve after sending HELLO
        # Keys remain at initial state for CLIENT_DATA in next round
        
        # STEP 2: GENERATE AND SEND SERVER_CHALLENGE
        challenge_nonce = os.urandom(16)
        enc_key, mac_key = session.get_send_keys()  # Initial S2C keys
        
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
        
        # STEP 3: EVOLVE S2C KEYS after sending SERVER_CHALLENGE
        session.evolve_send_keys(ciphertext, struct.pack('!B', 1))
        
        # STEP 4: TRANSITION STATE
        transition_state(session, ProtocolState.ACTIVE)
        
        logging.info(f"[Conn-{conn_id}] Sent SERVER_CHALLENGE (round {session.round_number})")
        logging.debug(f"[Conn-{conn_id}] Challenge nonce: {challenge_nonce.hex()}")
        
        return response, challenge_nonce
    
    def handle_client_data(self, session, msg_data, iv, conn_id):
        logging.info(f"[Conn-{conn_id}] Processing CLIENT_DATA from client {session.client_id}")
        
        # Use INITIAL C2S keys (not evolved from CLIENT_HELLO)
        # because client evolves its keys AFTER sending CLIENT_DATA
        enc_key, mac_key = session.get_recv_keys()
        
        # Log the received data for debugging
        logging.debug(f"[Conn-{conn_id}] Ciphertext: {hex_dump(msg_data['ciphertext'])}")
        logging.debug(f"[Conn-{conn_id}] HMAC: {hex_dump(msg_data['hmac'])}")
        logging.debug(f"[Conn-{conn_id}] IV: {iv.hex()}")
        
        plaintext = verify_and_decrypt(
            msg_data['ciphertext'],
            enc_key,
            mac_key,
            msg_data['header'],
            msg_data['hmac'],
            iv
        )
        
        if plaintext is None:
            log_security_event(
                "HMAC_VERIFICATION_FAILED",
                session.client_id,
                f"Round: {msg_data['round']}, Conn: {conn_id}, "
                f"Ciphertext: {hex_dump(msg_data['ciphertext'], 16)}, "
                f"HMAC: {hex_dump(msg_data['hmac'], 16)}",
                "CRITICAL"
            )
            session.terminate()
            return None
        
        if len(plaintext) < 4:
            log_security_event(
                "INVALID_PAYLOAD_LENGTH",
                session.client_id,
                f"Expected >= 4 bytes, got {len(plaintext)}, Conn: {conn_id}",
                "HIGH"
            )
            session.terminate()
            return None
        
        client_value = struct.unpack('!I', plaintext[:4])[0]
        logging.info(f"[Conn-{conn_id}] Received value: {client_value} from client {session.client_id}")
        
        round_num = msg_data['round']
        with self.lock:
            if round_num not in self.round_data:
                self.round_data[round_num] = []
            self.round_data[round_num].append(client_value)
        
        # NOW evolve C2S keys after successful CLIENT_DATA verification
        session.evolve_recv_keys(msg_data['ciphertext'], iv)
        
        return client_value
    
    def compute_aggregation(self, round_num):
        with self.lock:
            if round_num in self.round_data:
                values = self.round_data[round_num]
                total = sum(values)
                logging.debug(f"Aggregation for round {round_num}: {values} = {total}")
                return total
            return 0
    
    def send_aggregation(self, session, aggregated_value, conn, conn_id):
        payload = struct.pack('!I', aggregated_value)
        
        # Use evolved S2C keys (evolved after SERVER_CHALLENGE)
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
        
        session.evolve_send_keys(ciphertext, struct.pack('!I', aggregated_value))
        conn.sendall(response)
        
        logging.info(f"[Conn-{conn_id}] Sent aggregation result: {aggregated_value} to client {session.client_id}")
    
    def handle_connection(self, conn, addr):
        with self.lock:
            self.connection_counter += 1
            conn_id = self.connection_counter
        
        logging.info(f"[Conn-{conn_id}] NEW CONNECTION from {addr[0]}:{addr[1]}")
        
        try:
            # Receive CLIENT_HELLO
            data = conn.recv(4096)
            if not data:
                logging.warning(f"[Conn-{conn_id}] No data received, closing")
                return
            
            logging.debug(f"[Conn-{conn_id}] Received {len(data)} bytes: {hex_dump(data)}")
            
            msg_data = unpack_message(data)
            if msg_data is None:
                log_security_event(
                    "MALFORMED_MESSAGE",
                    "UNKNOWN",
                    f"Conn: {conn_id}, Data: {hex_dump(data, 16)}",
                    "HIGH"
                )
                return
            
            client_id = msg_data['client_id']
            logging.info(f"[Conn-{conn_id}] Message from client {client_id}, "
                        f"opcode={msg_data['opcode']}, round={msg_data['round']}")
            
            # Get or create session
            # In server.py, handle_connection method
            with self.lock:
                if client_id not in self.sessions or self.sessions[client_id].is_terminated():
                    # Create NEW session if none exists OR if previous was terminated
                    master_key = self.get_master_key(client_id)
                    if master_key is None:
                        log_security_event(
                            "UNKNOWN_CLIENT_ID",
                            client_id,
                            f"Conn: {conn_id}",
                            "HIGH"
                        )
                        return
                    self.sessions[client_id] = ClientSession(client_id, master_key)
                    logging.info(f"[Conn-{conn_id}] Created new session for client {client_id}")
                
                session = self.sessions[client_id]
            
            # Validate message state
            if not validate_message_state(session, msg_data['opcode'], 
                                         msg_data['round'], msg_data['direction'],
                                         Direction.CLIENT_TO_SERVER):
                log_security_event(
                    "STATE_VALIDATION_FAILED",
                    client_id,
                    f"Conn: {conn_id}, Opcode: {msg_data['opcode']}, "
                    f"Round: {msg_data['round']} (expected {session.round_number}), "
                    f"Direction: {msg_data['direction']}, State: {session.state.name}",
                    "HIGH"
                )
                session.terminate()
                return
            
            # Handle CLIENT_HELLO (with HMAC verification)
            if msg_data['opcode'] == Opcode.CLIENT_HELLO:
                response, nonce = self.handle_client_hello(session, msg_data, conn_id)
                if response is None:
                    logging.warning(f"[Conn-{conn_id}] CLIENT_HELLO authentication failed, terminating")
                    return
                conn.sendall(response)
            
            advance_round(session)
            
            # Receive CLIENT_DATA
            data = conn.recv(4096)
            if not data:
                logging.warning(f"[Conn-{conn_id}] No CLIENT_DATA received")
                return
            
            logging.debug(f"[Conn-{conn_id}] Received CLIENT_DATA: {hex_dump(data)}")
            
            msg_data = unpack_message(data)
            if msg_data is None:
                log_security_event(
                    "MALFORMED_CLIENT_DATA",
                    client_id,
                    f"Conn: {conn_id}, Data: {hex_dump(data, 16)}",
                    "HIGH"
                )
                session.terminate()
                return
            
            # Validate state
            if not validate_message_state(session, msg_data['opcode'],
                                         msg_data['round'], msg_data['direction'],
                                         Direction.CLIENT_TO_SERVER):
                log_security_event(
                    "CLIENT_DATA_STATE_INVALID",
                    client_id,
                    f"[Conn-{conn_id}] Opcode: {msg_data['opcode']}, "
                    f"Round: {msg_data['round']} (expected {session.round_number})",
                    "HIGH"
                )
                session.terminate()
                return
            
            # Handle CLIENT_DATA
            if msg_data['opcode'] == Opcode.CLIENT_DATA:
                client_value = self.handle_client_data(session, msg_data, msg_data['iv'], conn_id)
                
                if client_value is None:
                    logging.warning(f"[Conn-{conn_id}] Failed to process CLIENT_DATA")
                    return
                
                agg_value = self.compute_aggregation(msg_data['round'])
                self.send_aggregation(session, agg_value, conn, conn_id)
            
            logging.info(f"[Conn-{conn_id}] Session completed successfully for client {client_id}")
        
        except Exception as e:
            logging.error(f"[Conn-{conn_id}] Exception: {type(e).__name__}: {e}", exc_info=True)
            log_security_event(
                "EXCEPTION",
                "UNKNOWN",
                f"Conn: {conn_id}, Error: {e}",
                "CRITICAL"
            )
        finally:
            conn.close()
            logging.info(f"[Conn-{conn_id}] Connection closed")
    
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        logging.info(f"Server listening on {self.host}:{self.port}")
        logging.info("Press Ctrl+C to stop")
        logging.info("="*60)
        
        while True:
            try:
                conn, addr = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_connection,
                    args=(conn, addr),
                    name=f"Client-{addr[1]}"
                )
                client_thread.start()
            except KeyboardInterrupt:
                logging.info("\n" + "="*60)
                logging.info("Server shutting down")
                logging.info("="*60)
                break
        
        server_socket.close()


if __name__ == "__main__":
    server = SecureServer()
    server.start()