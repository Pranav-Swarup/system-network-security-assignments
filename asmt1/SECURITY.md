# Security Analysis – In Plain English

This protocol is designed to operate safely in a hostile network, where an attacker can read, modify, replay, delay, or inject packets. The goal is simple: even in that environment, messages should remain private, authentic, ordered, and resistant to manipulation.

What follows explains *how* each security property is achieved and *why* it works.

---

## 1. Confidentiality

**How messages stay secret:**  
Every message is encrypted using AES-128 in CBC mode with a fresh, random IV.

- Each message gets its own 16-byte random IV.
- Even if two plaintext messages are identical, their ciphertext will differ.
- The IV is sent in the clear, but that does not weaken security.

**What this stops:**

- Eavesdroppers only see random-looking bytes.
- Pattern matching (e.g., “this looks like the same message again”) fails.
- Known-plaintext attacks are ineffective because encryption is never deterministic.

**Why this is safe:**  
AES-128 is considered secure, and using a fresh IV per message prevents any useful structure from leaking.

---

## 2. Integrity and Authentication

**How tampering is detected:**  
Each message carries an HMAC-SHA256 over:

    Header || IV || Ciphertext

- The MAC key is different from the encryption key.
- The HMAC is verified in constant time.

**What this stops:**

- Bit-flipping attacks
- Message forgery
- Field substitution (round numbers, direction, opcodes, etc.)

**Why this is safe:**  
Without the MAC key, producing a valid HMAC is computationally infeasible. Any change to the message is immediately detected.

---

## 3. Replay Protection

**How replays are blocked:**  
Every message contains a monotonically increasing round number.

- Both sides track the *exact* round they expect.
- A message is accepted only if its round matches that expectation.
- The round number is covered by the HMAC, so it can’t be altered.

**What this stops:**

- Replaying old messages
- Injecting “future” messages
- Out-of-order delivery

**Example:**

    Attacker replays a valid Round 5 message  
    Protocol is now at Round 8  
    Server expects Round 8, receives Round 5  
    → Rejected immediately

---

## 4. Reordering Protection

**How order is enforced:**

- Only one specific round is valid at any time.
- The FSM ensures only the correct opcode is allowed in that round.
- There is no buffering or reassembly of out-of-order messages.

**What this stops:**

- Message reordering
- Protocol confusion
- State-skipping attacks

If Round 3 arrives before Round 2, it is rejected on sight.

---

## 5. Reflection Protection

**How self-reflection is prevented:**

- Each message includes a direction byte:
  - Client → Server: `0x01`
  - Server → Client: `0x02`
- The direction is included in the HMAC.

**What this stops:**

- Sending server messages back to the server
- Looping messages between endpoints
- Confusing one side into processing its own output

Since the direction is authenticated, an attacker cannot flip it.

---

## 6. Key Evolution (Forward Secrecy)

**How damage is limited:**  
After each successful round, keys are *ratcheted* forward:

    NewKey = H(OldKey || Context)

The context includes data from the current round (e.g., ciphertext).

- Keys only evolve after successful verification.
- Each direction evolves independently.
- Hashing is one-way.

**What this stops:**

- Decrypting past messages after a compromise
- Reconstructing old keys
- Long-term exposure from a single leak

If an attacker learns the Round 2 key, they still cannot:

- Decrypt Rounds 0 or 1
- Derive Round 3 without seeing Round 2 traffic

---

## 7. Padding Oracle Defense

**How padding leaks are avoided:**

- HMAC is verified *before* any decryption.
- Padding is never checked unless the HMAC is valid.
- All failures produce the same behavior: terminate the session.

**What this stops:**

- Padding oracle attacks
- Error-based side channels
- Timing-based feedback loops

An attacker never learns whether padding was “almost correct.”

---

## 8. Desynchronization Handling

**How confusion is avoided:**

- Any failure ends the session.
- No recovery or resynchronization exists.
- Keys are not evolved on failure.

**What this stops:**

- State manipulation
- Partial desync exploits
- Recovery-based attacks

If one side advances and the other does not, the next message fails and the session ends cleanly.

---

## 9. HMAC Tampering Resistance

This is the cryptographic backbone:

- 256-bit HMAC output
- Covers *everything* in the message
- Key never leaves the endpoints

It prevents:

- Bit-flips
- Field edits
- Ciphertext substitution

Forgery is computationally infeasible.

---

## 10. Multi-Client Isolation

Each client has:

- Its own master key
- Its own session state
- Its own evolving keys

The client ID is part of the authenticated header.

**This means:**

- One client cannot impersonate another.
- Sessions cannot be mixed.
- Compromise is contained to a single client.

---

## 11. FSM-Based Opcode Validation

The protocol follows a strict state machine:

    INIT → ACTIVE → TERMINATED

Each state allows only specific opcodes.

- Invalid opcode in any state = session termination
- No skipping steps
- No ambiguous transitions

This prevents protocol confusion and state abuse.

---

## 12. Malformed Message Rejection

The parser enforces:

- Minimum message size
- Fixed header length
- Exact IV length (16 bytes)
- Exact HMAC length (32 bytes)

This blocks:

- Truncated packets
- Oversized fields
- Structural attacks

---

## What This Protocol Guarantees

| Property              | How It’s Achieved                  |
|-----------------------|------------------------------------|
| Confidentiality       | AES-128-CBC + random IV            |
| Integrity             | HMAC-SHA256                        |
| Freshness             | Strict round numbers               |
| Replay resistance     | Round + HMAC                       |
| Ordering              | Round + FSM                        |
| Reflection resistance | Direction field                    |
| Forward secrecy       | Key ratcheting                     |
| Oracle resistance     | Authenticate-before-decrypt        |
| Fail-safe behavior    | Terminate on any anomaly           |

---

## What an Attacker *Can* and *Cannot* Do

An active attacker may:

- Drop packets
- Replay traffic
- Reorder messages
- Modify bytes
- Inject garbage

But the protocol ensures:

- Replays are rejected
- Modifications are detected
- Reordering fails
- Forgery is impossible
- Dropping packets only causes termination, not compromise

The only thing it cannot prevent is denial of service—because the network itself is hostile.

---

## Final Takeaway

This protocol achieves strong security using only symmetric cryptography by combining:

- Strict state tracking  
- Defense in depth  
- Authenticated encryption  
- Fail-secure design  
- One-way key evolution  

Every message is either *valid and safe* or *rejected and terminal*. There is no gray area—and that is exactly what makes it robust in an adversarial network.
