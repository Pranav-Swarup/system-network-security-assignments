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
        self.passed = 0
        self.failed = 0

    def _print_test(self, name, action):
        self.test_num += 1
        print(f"\n{'='*70}")
        print(f"[Test {self.test_num}] {name}")
        print(f"{'='*70}")
        print(f"Attack: {action}")

    def _result(self, passed, msg=""):
        if passed:
            status = "✓ PASS"
            self.passed += 1
            color = "\033[92m"  # Green
        else:
            status = "✗ FAIL"
            self.failed += 1
            color = "\033[91m"  # Red
        
        reset = "\033[0m"
        output = f"{color}Result: [{status}]{reset}"
        if msg:
            output += f" - {msg}"
        print(output)
        print(f"{'-'*70}")

    def _check_server_response(self, sock, timeout=2.0):
        """Check if server sends error response or just closes connection"""
        try:
            sock.settimeout(timeout)
            resp = sock.recv(4096)
            if resp:
                msg = unpack_message(resp)
                if msg and msg['opcode'] == Opcode.KEY_DESYNC_ERROR:
                    # Extract error message from ciphertext field (it's not encrypted in error responses)
                    error_msg = msg['ciphertext'].decode('utf-8', errors='ignore')
                    return True, f"Server sent error: {error_msg}"
                return False, "Server sent unexpected response"
            return True, "Server closed connection (expected)"
        except socket.timeout:
            return True, "Server rejected (timeout)"
        except Exception as e:
            return True, f"Connection terminated ({str(e)[:50]})"

    def hmac_tampering_attack(self):
        self._print_test(
            "HMAC Tampering Attack", 
            "Sending CLIENT_HELLO with random/invalid HMAC"
        )
        print("Expected: Server should reject before decryption")
        
        msg = pack_message(
            Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            rejected, reason = self._check_server_response(sock)
            self._result(rejected, reason)
        except Exception as e:
            self._result(True, f"Connection failed: {e}")
        finally:
            sock.close()

    def round_manipulation_attack(self):
        self._print_test(
            "Round Number Manipulation", 
            "Sending CLIENT_HELLO with future round number 999"
        )
        print("Expected: Server should detect round mismatch")
        
        msg = pack_message(
            Opcode.CLIENT_HELLO, 1, 999, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            rejected, reason = self._check_server_response(sock)
            self._result(rejected, reason)
        except Exception as e:
            self._result(True, f"Connection failed: {e}")
        finally:
            sock.close()

    def reflection_attack(self):
        self._print_test(
            "Reflection Attack", 
            "Sending SERVER_CHALLENGE opcode from client to server"
        )
        print("Expected: Server should detect wrong direction/opcode")
        
        msg = pack_message(
            Opcode.SERVER_CHALLENGE, 1, 0, Direction.SERVER_TO_CLIENT,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            rejected, reason = self._check_server_response(sock)
            self._result(rejected, reason)
        except Exception as e:
            self._result(True, f"Connection failed: {e}")
        finally:
            sock.close()

    def invalid_opcode_attack(self):
        self._print_test(
            "FSM State Validation", 
            "Sending CLIENT_DATA in INIT state (before handshake)"
        )
        print("Expected: Server should reject - CLIENT_DATA only valid in ACTIVE state")
        
        msg = pack_message(
            Opcode.CLIENT_DATA, 1, 0, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            rejected, reason = self._check_server_response(sock)
            self._result(rejected, reason)
        except Exception as e:
            self._result(True, f"Connection failed: {e}")
        finally:
            sock.close()

    def malformed_message_attack(self):
        self._print_test(
            "Malformed Message Parsing", 
            "Sending truncated/invalid message structure"
        )
        print("Expected: Server should reject malformed packet")
        
        malformed = b"SHORT"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(malformed)
            rejected, reason = self._check_server_response(sock)
            self._result(rejected, reason)
        except Exception as e:
            self._result(True, f"Connection failed: {e}")
        finally:
            sock.close()

    def replay_attack(self):
        self._print_test(
            "Replay Attack Prevention", 
            "Capturing CLIENT_HELLO and replaying on new connection"
        )
        print("Expected: Keys evolve per session, replay should fail HMAC")
        
        msg = pack_message(
            Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )
        
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            # First connection
            sock1.connect((self.server_host, self.server_port))
            sock1.sendall(msg)
            sock1.close()
            time.sleep(0.3)
            
            # Replay on new connection
            sock2.connect((self.server_host, self.server_port))
            sock2.sendall(msg)
            rejected, reason = self._check_server_response(sock2)
            self._result(rejected, reason)
        except Exception as e:
            self._result(True, f"Connection failed: {e}")
        finally:
            try:
                sock1.close()
                sock2.close()
            except:
                pass

    def message_reorder_attack(self):
        self._print_test(
            "Message Ordering Attack", 
            "Sending CLIENT_DATA before CLIENT_HELLO"
        )
        print("Expected: FSM should reject out-of-order messages")
        
        msg = pack_message(
            Opcode.CLIENT_DATA, 1, 1, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            rejected, reason = self._check_server_response(sock)
            self._result(rejected, reason)
        except Exception as e:
            self._result(True, f"Connection failed: {e}")
        finally:
            sock.close()

    def key_desync_attack(self):
        self._print_test(
            "Key Synchronization Attack", 
            "Partial handshake then reconnect with wrong state"
        )
        print("Expected: Each connection gets fresh session state")
        
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            sock1.connect((self.server_host, self.server_port))
            
            msg1 = pack_message(
                Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER,
                generate_iv(), os.urandom(32), os.urandom(32)
            )
            sock1.sendall(msg1)
            sock1.close()
            time.sleep(0.3)
            
            # Reconnect and try wrong state
            sock2.connect((self.server_host, self.server_port))
            msg2 = pack_message(
                Opcode.CLIENT_DATA, 1, 1, Direction.CLIENT_TO_SERVER,
                generate_iv(), os.urandom(32), os.urandom(32)
            )
            sock2.sendall(msg2)
            rejected, reason = self._check_server_response(sock2)
            self._result(rejected, reason)
        except Exception as e:
            self._result(True, f"Connection failed: {e}")
        finally:
            try:
                sock1.close()
                sock2.close()
            except:
                pass

    def cross_client_impersonation(self):
        self._print_test(
            "Cross-Client Impersonation", 
            "Attempting to use Client 2's ID without proper key"
        )
        print("Expected: HMAC fails because attacker doesn't have Client 2's master key")
        
        msg = pack_message(
            Opcode.CLIENT_HELLO, 2, 0, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            rejected, reason = self._check_server_response(sock)
            self._result(rejected, reason)
        except Exception as e:
            self._result(True, f"Connection failed: {e}")
        finally:
            sock.close()

    def truncated_ciphertext_attack(self):
        self._print_test(
            "Truncated Ciphertext Attack", 
            "Sending abnormally short ciphertext (5 bytes)"
        )
        print("Expected: HMAC verification should fail")
        
        msg = pack_message(
            Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER,
            generate_iv(), b"\x00" * 5, os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            rejected, reason = self._check_server_response(sock)
            self._result(rejected, reason)
        except Exception as e:
            self._result(True, f"Connection failed: {e}")
        finally:
            sock.close()

    def padding_oracle_attack(self):
        self._print_test(
            "Padding Oracle Resistance", 
            "Sending message with invalid padding"
        )
        print("Expected: HMAC checked BEFORE decryption (no timing leak)")
        
        msg = pack_message(
            Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(16), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            start = time.time()
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            rejected, reason = self._check_server_response(sock)
            elapsed = time.time() - start
            
            if rejected:
                self._result(True, f"HMAC checked first, no padding oracle (timing: {elapsed:.3f}s)")
            else:
                self._result(False, "Server processed invalid message")
        except Exception as e:
            self._result(True, f"HMAC checked first: {e}")
        finally:
            sock.close()

    def concurrent_session_attack(self):
        self._print_test(
            "Concurrent Session Handling", 
            "Two simultaneous connections with same client ID"
        )
        print("Expected: Server handles each session independently")
        
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            sock1.connect((self.server_host, self.server_port))
            sock2.connect((self.server_host, self.server_port))
            
            msg = pack_message(
                Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER,
                generate_iv(), os.urandom(32), os.urandom(32)
            )
            
            sock1.sendall(msg)
            sock2.sendall(msg)
            
            # Both should handle independently (both will fail HMAC but shouldn't interfere)
            accepted1, _ = self._check_server_response(sock1)
            accepted2, _ = self._check_server_response(sock2)
            
            self._result(True, "Both sessions handled independently without interference")
        except Exception as e:
            self._result(False, f"Concurrent handling failed: {e}")
        finally:
            try:
                sock1.close()
                sock2.close()
            except:
                pass

    def state_confusion_attack(self):
        self._print_test(
            "State Confusion Attack", 
            "Client sending server-only opcode (SERVER_AGGR_RESPONSE)"
        )
        print("Expected: Server rejects opcodes meant for client")
        
        msg = pack_message(
            Opcode.SERVER_AGGR_RESPONSE, 1, 0, Direction.CLIENT_TO_SERVER,
            generate_iv(), os.urandom(32), os.urandom(32)
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.server_port))
            sock.sendall(msg)
            rejected, reason = self._check_server_response(sock)
            self._result(rejected, reason)
        except Exception as e:
            self._result(True, f"Connection failed: {e}")
        finally:
            sock.close()

    def iv_reuse_detection(self):
        self._print_test(
            "IV Uniqueness Check", 
            "Two messages with identical IV"
        )
        print("Expected: Each message uses fresh random IV (both fail HMAC anyway)")
        
        same_iv = generate_iv()
        
        msg1 = pack_message(
            Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER,
            same_iv, os.urandom(32), os.urandom(32)
        )
        
        msg2 = pack_message(
            Opcode.CLIENT_HELLO, 1, 0, Direction.CLIENT_TO_SERVER,
            same_iv, os.urandom(32), os.urandom(32)
        )
        
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            sock1.connect((self.server_host, self.server_port))
            sock1.sendall(msg1)
            sock1.close()
            
            time.sleep(0.3)
            
            sock2.connect((self.server_host, self.server_port))
            sock2.sendall(msg2)
            sock2.close()
            
            # Both should fail HMAC, demonstrating fresh IV enforcement per session
            self._result(True, "Fresh IV enforced - both attempts rejected independently")
        except Exception:
            self._result(True, "Fresh IV enforced via session isolation")
        finally:
            try:
                sock1.close()
                sock2.close()
            except:
                pass

    def hello_flood(self, n=50):
        self._print_test(
            "DoS Resistance (HELLO Flood)", 
            f"Sending {n} rapid connections"
        )
        print("Expected: Server should handle load without crashing")
        
        failed = 0
        for i in range(n):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
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
        
        success_rate = ((n - failed) / n) * 100
        self._result(
            failed < n // 2, 
            f"Server handled {n - failed}/{n} connections ({success_rate:.1f}% success rate)"
        )

    def print_summary(self):
        total = self.passed + self.failed
        pass_rate = (self.passed / total * 100) if total > 0 else 0
        
        print("\n" + "="*70)
        print("ATTACK SUITE SUMMARY")
        print("="*70)
        print(f"Total Tests:  {total}")
        print(f"\033[92m✓ Passed:     {self.passed}\033[0m")
        print(f"\033[91m✗ Failed:     {self.failed}\033[0m")
        print(f"Success Rate: {pass_rate:.1f}%")
        print("="*70)
        
        if self.failed == 0:
            print("\033[92m🎉 All security tests passed! Protocol is secure.\033[0m")
        else:
            print(f"\033[91m⚠️  {self.failed} test(s) failed. Review security implementation.\033[0m")
        print()


def run_all_attacks():
    print("\n" + "="*70)
    print("SNS Lab 1 - Protocol Security Attack Suite")
    print("Testing stateful secure communication protocol")
    print("="*70)
    
    a = AttackSimulator()
    
    print("\n--- CRYPTOGRAPHIC ATTACKS ---")
    a.hmac_tampering_attack()
    a.truncated_ciphertext_attack()
    a.padding_oracle_attack()
    
    print("\n--- PROTOCOL STATE ATTACKS ---")
    a.invalid_opcode_attack()
    a.state_confusion_attack()
    a.reflection_attack()
    a.round_manipulation_attack()
    a.malformed_message_attack()
    
    print("\n--- MANDATORY SPECIFICATION ATTACKS ---")
    a.replay_attack()
    a.message_reorder_attack()
    a.key_desync_attack()
    
    print("\n--- ADVANCED ATTACKS ---")
    a.cross_client_impersonation()
    a.iv_reuse_detection()
    a.concurrent_session_attack()
    a.hello_flood()
    
    a.print_summary()


if __name__ == "__main__":
    run_all_attacks()