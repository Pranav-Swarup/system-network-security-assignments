# Security Analysis

## Protocol Security Properties

This document analyzes how the implemented protocol achieves security against various attack scenarios in a hostile network environment.

## 1. Confidentiality

**Mechanism:** AES-128-CBC encryption with fresh random IVs

**How it works:**
- Every message uses a unique 16-byte random IV
- AES-128 provides strong encryption (128-bit security level)
- CBC mode ensures blocks are chained together
- Different IVs ensure identical plaintexts encrypt differently

**Protection against:**
- Eavesdropping: Adversary sees only ciphertext
- Pattern analysis: Same plaintext produces different ciphertexts
- Known-plaintext attacks: IV randomization prevents this

**Why it's secure:**
- IV is transmitted in cleartext but doesn't compromise security
- AES-128 has no known practical attacks
- Fresh IV per message prevents deterministic encryption

## 2. Integrity and Authentication

**Mechanism:** HMAC-SHA256 over entire message

**How it works:**
- HMAC computed over: `Header || IV || Ciphertext`
- 256-bit output provides strong authentication
- MAC key separate from encryption key
- Constant-time comparison prevents timing attacks

**Protection against:**
- Message tampering: Any bit change invalidates HMAC
- Forgery: Cannot create valid HMAC without MAC key
- Substitution: HMAC binds ciphertext to header fields

**Why it's secure:**
- HMAC-SHA256 has no known collision attacks
- Separate MAC key prevents related-key attacks
- Covers all fields including round number and direction

## 3. Replay Attack Prevention

**Mechanism:** Strict round number enforcement

**How it works:**
- Each message includes monotonically increasing round number
- Server/client maintain expected round in state
- Message accepted only if round matches expected value
- Round incremented only after successful exchange

**Protection against:**
- Replay attacks: Old messages have wrong round number
- Out-of-order delivery: Only current round accepted
- Message injection: Future rounds rejected

**Why it's secure:**
- Round number is HMAC-protected (cannot be modified)
- State-based validation prevents acceptance
- No "grace period" for old messages

**Attack scenario:**
```
Adversary captures valid message at Round 5
Later replays it when protocol is at Round 8
Server checks: expected Round 8, received Round 5
Result: Message rejected, session terminated
```

## 4. Message Reordering Prevention

**Mechanism:** Strict sequencing via round numbers and FSM

**How it works:**
- Messages must arrive in exact round order
- FSM validates opcode for current state
- No buffering of out-of-order messages

**Protection against:**
- Reordering: Only sequential rounds accepted
- Protocol confusion: FSM enforces valid transitions

**Why it's secure:**
- Combined round + FSM validation
- Single expected message at any time
- No ambiguity in protocol state

**Attack scenario:**
```
Adversary intercepts Round 2 and Round 3 messages
Delivers Round 3 before Round 2
Server at Round 2: expects Round 2, receives Round 3
Result: Rejected immediately
```

## 5. Reflection Attack Prevention

**Mechanism:** Direction field validation

**How it works:**
- Each message includes direction byte
- Server expects CLIENT_TO_SERVER (0x01)
- Client expects SERVER_TO_CLIENT (0x02)
- Direction is HMAC-protected

**Protection against:**
- Message reflection: Wrong direction detected
- Self-messaging: Cannot send own messages back

**Why it's secure:**
- Direction included in HMAC computation
- Cannot modify without breaking HMAC
- Symmetric but directional keys add extra layer

**Attack scenario:**
```
Adversary captures server response
Sends it back to server
Server checks: expects direction 0x01, receives 0x02
Result: Rejected as invalid direction
```

## 6. Key Evolution (Forward Secrecy)

**Mechanism:** Ratcheting keys after each successful round

**How it works:**
- Keys derived using: `New_Key = H(Old_Key || Context)`
- Context includes ciphertext or nonce from current round
- Evolution happens only after successful verification
- Separate evolution for each direction

**Protection against:**
- Key compromise: Old messages cannot be decrypted
- Future compromise: Past keys cannot be recovered
- Long-term key exposure: Limits damage scope

**Why it's secure:**
- One-way hash function prevents key recovery
- Context binding prevents state manipulation
- Failure prevents evolution (no desync on attack)

**Key evolution example:**
```
Round 0: C2S_Enc_0 = H(Master_Key || "C2S-ENC")
Round 1: C2S_Enc_1 = H(C2S_Enc_0 || Ciphertext_0)
Round 2: C2S_Enc_2 = H(C2S_Enc_1 || Ciphertext_1)
...

If Round 2 key is compromised:
- Cannot decrypt Round 0 or Round 1 messages (forward secrecy)
- Cannot derive Round 3+ keys without seeing Round 2 ciphertext
```

## 7. Padding Oracle Prevention

**Mechanism:** Authenticate-then-Encrypt with HMAC verification first

**How it works:**
- HMAC verified BEFORE any decryption
- Padding validation happens after HMAC check
- Same error response for all HMAC failures
- Session terminated on any validation failure

**Protection against:**
- Padding oracle: HMAC fails before padding checked
- Timing attacks: Constant-time HMAC comparison
- Error message analysis: Uniform error handling

**Why it's secure:**
- No information leakage from padding errors
- Decryption never attempted with invalid HMAC
- Single code path for all authentication failures

**Attack scenario:**
```
Adversary sends message with invalid padding
Server checks HMAC first: HMAC invalid
Server never reaches padding validation
Adversary learns nothing about padding
Session terminated immediately
```

## 8. State Desynchronization Handling

**Mechanism:** Permanent session termination on any failure

**How it works:**
- Any validation failure terminates session
- No recovery or resynchronization attempts
- Keys not evolved on failure
- Clear separation between success/failure paths

**Protection against:**
- Desync attacks: Session ends rather than continuing
- State confusion: No ambiguous states exist
- Recovery exploits: No recovery mechanism to exploit

**Why it's secure:**
- Conservative failure handling
- No partial state updates
- Clear security boundary (success or termination)

**Attack scenario:**
```
Adversary drops a message mid-protocol
Client evolves keys, server does not
Next message: client uses Round N+1, server expects Round N
Result: Round mismatch detected, session terminated
```

## 9. HMAC Tampering Protection

**Mechanism:** Cryptographic message authentication

**How it works:**
- 256-bit HMAC provides collision resistance
- MAC key shared only between client-server pair
- Covers all message fields (header + ciphertext)

**Protection against:**
- Bit flipping: Changes invalidate HMAC
- Field modification: Round/opcode protected
- Ciphertext substitution: Detected immediately

**Why it's secure:**
- HMAC-SHA256 computationally infeasible to forge
- No known collision attacks
- Key not derivable from MAC values

## 10. Multi-Client Isolation

**Mechanism:** Per-client session state and keys

**How it works:**
- Each client has unique master key
- Separate session state per client
- Client ID in message header (HMAC-protected)
- Server maintains isolated session dictionary

**Protection against:**
- Cross-client attacks: Different keys per client
- Session hijacking: Client ID authenticated
- Data mixing: Aggregation uses evolved keys

**Why it's secure:**
- No shared cryptographic material between clients
- Session state cannot be transferred
- Client ID cannot be forged (in HMAC)

## 11. Opcode Validation via FSM

**Mechanism:** Finite State Machine with strict transitions

**How it works:**
- Protocol states: INIT → ACTIVE → TERMINATED
- Each state allows specific opcodes only
- Opcode validated before processing
- Invalid opcode terminates session

**Protection against:**
- Protocol confusion: FSM enforces valid flow
- State manipulation: Opcodes tied to states
- Premature transitions: Cannot skip states

**Valid transitions:**
```
INIT state: Only CLIENT_HELLO allowed
  → Send SERVER_CHALLENGE
  → Transition to ACTIVE

ACTIVE state: CLIENT_DATA or TERMINATE allowed
  → Process data and aggregate
  → Send SERVER_AGGR_RESPONSE
  → Can continue or terminate

TERMINATED: No opcodes accepted, session ended
```

## 12. Malformed Message Rejection

**Mechanism:** Strict message format validation

**How it works:**
- Minimum message size enforced (55 bytes)
- Fixed header size (7 bytes)
- IV size exactly 16 bytes
- HMAC size exactly 32 bytes
- Parsing validates all size constraints

**Protection against:**
- Buffer attacks: Size checks prevent overflow
- Truncated messages: Minimum size enforced
- Oversized fields: Fixed sizes validated

## Summary of Security Guarantees

| Property | Mechanism | Strength |
|----------|-----------|----------|
| Confidentiality | AES-128-CBC + Random IV | 128-bit |
| Integrity | HMAC-SHA256 | 256-bit |
| Freshness | Round numbers | Strict monotonic |
| Forward Secrecy | Key ratcheting | One-way hash |
| Replay Prevention | Round + HMAC | Cryptographic |
| Reorder Prevention | FSM + Round | State-based |
| Reflection Prevention | Direction field | Protocol-level |
| Padding Oracle | Encrypt-then-MAC | No oracle |
| Desync Resistance | Immediate termination | Fail-secure |

## Threat Model Coverage

**Active Adversary Capabilities:**
- ✓ Replay messages: Detected by round numbers
- ✓ Modify ciphertexts: Detected by HMAC
- ✓ Drop packets: Causes desync → termination
- ✓ Reorder messages: Detected by round numbers
- ✓ Reflect messages: Detected by direction field
- ✓ Inject messages: Cannot forge valid HMAC
- ✓ Analyze traffic: Encryption provides confidentiality

**Limitations (by design):**
- Cannot prevent DoS (adversary controls network)
- No recovery from desynchronization (fail-secure design)
- Requires pre-shared keys (no PKI available)

## Conclusion

The protocol achieves strong security properties using only symmetric cryptography by combining:
- Stateful design with strict validation
- Defense-in-depth (multiple validation layers)
- Fail-secure philosophy (terminate on any doubt)
- Key evolution for forward secrecy
- Authenticated encryption with proper ordering

All attacks in the threat model are effectively mitigated through the combined use of cryptographic primitives and protocol-level mechanisms.