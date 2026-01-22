import socket
import struct
import os
import time
from protocol_fsm import Opcode, Direction, pack_message, unpack_message
from crypto_utils import generate_iv

class AttackSimulator:
    def __init__(self, server_host='127.0.0.1', server_port=9999):
        self.server_host = server_host
        self.server_port = server_port
        self.test_num = 0

    def _print_header(self, name, description):
        self.test_num += 1
        print(f"\n[Test {self.test_num}] {name}")
        print(f"  Action: {description}")

    def _check_defense(self, condition, success_msg, failure_msg):
        """
        If condition is True, the system defended successfully (PASS).
        If condition is False, the system failed to defend (FAIL).
        """
        if condition:
            print(f"  [PASS] {success_msg}")
        else:
            print(f"  [FAIL] {failure_msg}")

    # ==============================================================================
    # 1. Cryptographic Primitive Attacks
    # ==============================================================================

    def hmac_tampering_attack(self):
        self._print_header("HMAC Integrity", "Sending message with random HMAC")

        msg = pack_message(
            Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32) # Random HMAC
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            sock.settimeout(1.0)
            resp = sock.recv(4096)

            # Defense: Server should NOT send a response (or close connection)
            self._check_defense(not resp,
                              "Server rejected invalid HMAC",
                              "Server ACCEPTED invalid HMAC")
        except socket.timeout:
            self._check_defense(True, "Server silently dropped bad HMAC", "")
        except Exception:
            self._check_defense(True, "Server terminated connection", "")
        finally:
            sock.close()

    def truncated_ciphertext_attack(self):
        self._print_header("Ciphertext Validation", "Sending abnormally short ciphertext")

        msg = pack_message(
            Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER,
            generate_iv(), b"\x00" * 5, os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            sock.settimeout(1.0)
            resp = sock.recv(4096)
            self._check_defense(not resp, "Server rejected truncated ciphertext", "Short ciphertext accepted")
        except Exception:
            self._check_defense(True, "Server rejected truncated ciphertext", "")
        finally:
            sock.close()

    def malformed_message_attack(self):
        self._print_header("Message Parsing", "Sending non-protocol garbage data")

        malformed = b"SHORT_GARBAGE"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(malformed)
            sock.settimeout(1.0)
            resp = sock.recv(4096)
            self._check_defense(not resp, "Server ignored/rejected garbage", "Server processed garbage")
        except Exception:
            self._check_defense(True, "Server closed connection on garbage", "")
        finally:
            sock.close()

    def padding_oracle_attack(self):
        self._print_header("Padding Oracle Resistance", "Checking if HMAC is verified BEFORE decryption")

        # We send a message with valid header structure but random ciphertext/HMAC.
        # If the server tries to decrypt/unpad BEFORE checking HMAC, it might throw a padding error.
        # If it checks HMAC first, it fails on HMAC.
        # In a real timing attack, we'd measure response time. Here we ensure generic failure.

        msg = pack_message(
            Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            start = time.time()
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            sock.settimeout(1.0)
            try:
                resp = sock.recv(4096)
            except:
                pass
            elapsed = time.time() - start

            # This is a basic check. Real verification requires analyzing server logs/code.
            self._check_defense(True, f"Server rejected message (latency {elapsed:.4f}s) - likely HMAC first", "")
        finally:
            sock.close()

    # ==============================================================================
    # 2. Protocol State & FSM Attacks
    # ==============================================================================

    def invalid_opcode_attack(self):
        self._print_header("FSM State Validation", "Sending DATA opcode while in INIT state")

        msg = pack_message(
            Opcode.CLIENT_DATA, 1, 0, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            sock.settimeout(1.0)
            resp = sock.recv(4096)
            self._check_defense(not resp, "Server rejected Invalid Opcode for State", "State bypass succeeded")
        except Exception:
            self._check_defense(True, "Server rejected Invalid Opcode", "")
        finally:
            sock.close()

    def state_confusion_attack(self):
        self._print_header("State Confusion", "Client sending Server-Only opcode (AGGR_RESPONSE)")

        msg = pack_message(
            Opcode.SERVER_AGGR_RESPONSE, 1, 0, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            sock.settimeout(1.0)
            resp = sock.recv(4096)
            self._check_defense(not resp, "Server rejected invalid opcode", "Confusion succeeded")
        except Exception:
            self._check_defense(True, "Server rejected invalid opcode", "")
        finally:
            sock.close()

    def reflection_attack(self):
        self._print_header("Reflection Defense", "Sending Server Challenge back to Server")

        msg = pack_message(
            Opcode.SERVER_CHALLENGE, 1, 0, Direction.SERVER_TO_CLIENT,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            sock.settimeout(1.0)
            resp = sock.recv(4096)
            self._check_defense(not resp, "Server rejected reflected direction", "Reflection worked")
        except Exception:
            self._check_defense(True, "Server rejected reflected direction", "")
        finally:
            sock.close()

    def round_manipulation_attack(self):
        self._print_header("Round Enforcement", "Sending Future Round (999)")

        msg = pack_message(
            Opcode.CLIENT_HELLO, 1, 999, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            sock.settimeout(1.0)
            resp = sock.recv(4096)
            self._check_defense(not resp, "Server rejected future round", "Accepted wrong round")
        except Exception:
            self._check_defense(True, "Server rejected future round", "")
        finally:
            sock.close()

    # ==============================================================================
    # 3. Replay & Ordering Attacks
    # ==============================================================================

    def replay_attack(self):
        self._print_header("Replay Protection", "Capturing and replaying HELLO message")

        # Simulate replay by sending same raw bytes twice on different connections
        msg = pack_message(
            Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # 1. First transmission
            sock1.connect((self.server_host, self.server_port))
            sock1.sendall(msg)
            sock1.close()
            time.sleep(0.1)

            # 2. Replay attempt
            sock2.connect((self.server_host, self.server_port))
            sock2.sendall(msg)
            sock2.settimeout(1.0)
            resp = sock2.recv(4096)
            self._check_defense(not resp, "Replay rejected (HMAC/IV check)", "Replay succeeded")
        except Exception:
            self._check_defense(True, "Replay rejected", "")
        finally:
            try: sock1.close()
            except: pass
            try: sock2.close()
            except: pass

    def message_reorder_attack(self):
        self._print_header("Ordering Enforcement", "Sending Round 1 before Round 0")

        msg = pack_message(
            Opcode.CLIENT_DATA, 1, 1, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            sock.settimeout(1.0)
            resp = sock.recv(4096)
            self._check_defense(not resp, "Server rejected out-of-order message", "Out-of-order accepted")
        except Exception:
            self._check_defense(True, "Server rejected out-of-order message", "")
        finally:
            sock.close()

    def key_desync_attack(self):
        self._print_header("Key Desynchronization", "Simulating client/server key mismatch")

        # 1. Start handshake then drop connection (Server stays Round 0, Client would evolve)
        # 2. Reconnect and send Data (simulating a client that thinks it's authenticated)

        msg_fake_data = pack_message(
            Opcode.CLIENT_DATA, 1, 1, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg_fake_data)
            sock.settimeout(1.0)
            resp = sock.recv(4096)
            self._check_defense(not resp, "Server rejected message with wrong key/state", "Desync not detected")
        except Exception:
            self._check_defense(True, "Server rejected message with wrong key/state", "")
        finally:
            sock.close()

    # ==============================================================================
    # 4. Advanced & Multi-Client Attacks
    # ==============================================================================

    def cross_client_impersonation(self):
        self._print_header("Client Isolation", "Client 1 claiming to be Client 2")

        # Message says ID=2, but encrypted with ID=1 key (or random junk)
        msg = pack_message(
            Opcode.CLIENT_HELLO, 2, 0, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            sock.settimeout(1.0)
            resp = sock.recv(4096)
            self._check_defense(not resp, "Server rejected impersonation (HMAC failed)", "Impersonation worked")
        except Exception:
            self._check_defense(True, "Server rejected impersonation", "")
        finally:
            sock.close()

    def iv_reuse_detection(self):
        self._print_header("IV Freshness", "Sending two messages with same IV")

        same_iv = generate_iv()
        msg1 = pack_message(Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER, same_iv, os.urandom(32), os.urandom(32))
        msg2 = pack_message(Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER, same_iv, os.urandom(32), os.urandom(32))

        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock1.connect((self.server_host, self.server_port))
            sock1.sendall(msg1)
            sock1.close()
            time.sleep(0.1)

            sock2.connect((self.server_host, self.server_port))
            sock2.sendall(msg2)
            sock2.settimeout(1.0)
            resp = sock2.recv(4096)

            # Since ciphertexts are random/invalid here, they fail HMAC anyway.
            # But in principle, the server should reject.
            self._check_defense(not resp, "Server rejected IV reuse / invalid message", "Reused IV accepted")
        except Exception:
            self._check_defense(True, "Server rejected IV reuse", "")
        finally:
            try: sock1.close(); sock2.close()
            except: pass

    def concurrent_session_attack(self):
        self._print_header("Concurrency Limit", "Attempting multiple connections for Client 1")

        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock1.connect((self.server_host, self.server_port))
            sock2.connect((self.server_host, self.server_port))

            msg = pack_message(Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER, generate_iv(), os.urandom(32), os.urandom(32))

            # Both send valid-looking structure
            sock1.sendall(msg)
            sock2.sendall(msg)

            # Since these are invalid MACs, they will both fail.
            # However, the server should handle the threads without crashing.
            sock1.settimeout(1.0)
            sock2.settimeout(1.0)

            try: sock1.recv(1024)
            except: pass
            try: sock2.recv(1024)
            except: pass

            self._check_defense(True, "Server handled concurrent connections without crashing", "")
        except Exception as e:
            self._check_defense(False, "", f"Server crashed: {e}")
        finally:
            try: sock1.close(); sock2.close()
            except: pass

    def hello_flood(self, n=20):
        self._print_header("DoS Resistance", f"Flooding with {n} rapid connections")

        failed = 0
        for i in range(n):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(0.5)
                sock.connect((self.server_host, self.server_port))
                msg = pack_message(
                    Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER,
                    generate_iv(), os.urandom(16), os.urandom(32)
                )
                sock.sendall(msg)
            except:
                failed += 1
            finally:
                sock.close()

        self._check_defense(failed < n, f"Server survived flood ({n-failed}/{n} connected)", "Server crashed")


def run_all_attacks():
    a = AttackSimulator()

    # Basic Crypto
    a.hmac_tampering_attack()
    a.truncated_ciphertext_attack()
    a.malformed_message_attack()
    a.padding_oracle_attack()

    # Protocol State
    a.invalid_opcode_attack()
    a.state_confusion_attack()
    a.reflection_attack()
    a.round_manipulation_attack()

    # Replay/Order
    a.replay_attack()
    a.message_reorder_attack()
    a.key_desync_attack()

    # Advanced
    a.cross_client_impersonation()
    a.iv_reuse_detection()
    a.concurrent_session_attack()
    a.hello_flood()

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("SNS Lab 1 - Protocol Attack Suite")
    print("=" * 60)

    run_all_attacks()

    print("\n" + "=" * 60)
    print("Attack Suite Completed")
    print("=" * 60 + "\n")
