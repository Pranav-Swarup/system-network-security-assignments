# Secure Multi-Client Communication Protocol

## Overview

This project implements a stateful, symmetric-key-based secure communication protocol for a server communicating with multiple clients in a hostile network environment.

## Features

- **AES-128-CBC encryption** with manual PKCS#7 padding
- **HMAC-SHA256** for message authentication
- **Key ratcheting** (forward secrecy through key evolution)
- **Replay protection** via round numbers
- **Stateful protocol** with FSM validation
- **Multi-client aggregation** with per-client encryption

## Requirements

```
Python 3.8+
cryptography>=41.0.0
```

## Installation

```bash
pip install cryptography
```

## Project Structure

```
.
├── crypto_utils.py      # Cryptographic primitives (AES, HMAC, padding)
├── protocol_fsm.py      # Protocol state machine and message format
├── server.py           # Multi-client server implementation
├── client.py           # Client implementation
├── attacks.py          # Attack simulation scenarios
├── README.md           # This file
└── SECURITY.md         # Security analysis
```

## Usage

### Running the Server

```bash
python server.py
```

The server will:
- Listen on `127.0.0.1:9999`
- Print master keys for each client (for testing only)
- Handle multiple concurrent client connections

### Running a Client

Note: ``-i`` flag can be passed at the end in place of value for an interactive session. 

```bash
python client.py <client_id> <master_key_hex> [data_value]
```

Example:
```bash
# Using the master key printed by server for client 1
python client.py 1 a1b2c3d4e5f6... 42
```

Parameters:
- `client_id`: Integer identifier (1, 2, or 3)
- `master_key_hex`: 32-character hex string (16 bytes)
- `data_value`: Optional numeric value to send (default: 100)

### Running Multiple Clients

Open separate terminals:

```bash
# Terminal 1
python server.py

# Terminal 2
python client.py 1 <key1_hex> 100

# Terminal 3
python client.py 2 <key2_hex> 200

# Terminal 4
python client.py 3 <key3_hex> 300
```

The server aggregates all client data and sends the sum back to each client.

### Running Attack Simulations

```bash
python attacks.py
```

This demonstrates various attack scenarios and shows how the protocol mitigates them.

## Protocol Flow

1. **Client → Server: CLIENT_HELLO**
   - Client initiates connection
   - Round = 0, encrypted with initial C2S keys

2. **Server → Client: SERVER_CHALLENGE**
   - Server sends encrypted challenge
   - Round = 0, encrypted with initial S2C keys
   - Transitions to ACTIVE state

3. **Client → Server: CLIENT_DATA**
   - Client sends numeric data
   - Round = 1, encrypted with evolved C2S keys
   - Keys evolved after successful send

4. **Server → Client: SERVER_AGGR_RESPONSE**
   - Server sends aggregated result
   - Round = 2, encrypted with evolved S2C keys
   - Keys evolved after successful send

## Key Evolution

Keys evolve after each successful message:

**Client → Server:**
```
C2S_Enc_{R+1} = H(C2S_Enc_R || Ciphertext_R)
C2S_Mac_{R+1} = H(C2S_Mac_R || Nonce_R)
```

**Server → Client:**
```
S2C_Enc_{R+1} = H(S2C_Enc_R || AggregatedData_R)
S2C_Mac_{R+1} = H(S2C_Mac_R || StatusCode_R)
```

Keys are **only** updated after successful verification, decryption, and validation.

## Error Handling

Any of the following causes immediate session termination:
- HMAC verification failure
- Round number mismatch
- Invalid opcode for current state
- Wrong message direction
- Malformed message structure
- Invalid padding

## Testing

To verify correct operation:

1. Start server
2. Run 3 clients with different values
3. Verify each client receives correct aggregated sum
4. Run attack simulations to verify security

Expected output shows:
- Each client successfully completes protocol
- All attacks are rejected/detected
- Sessions terminate on any validation failure

## Notes

- Master keys are printed by server for testing only
- In production, keys would be securely pre-shared
- All cryptographic operations use secure random IVs
- HMAC is verified BEFORE decryption (prevent oracle attacks)
- Session state is permanently terminated on any error

## Troubleshooting

**"Connection refused"**
- Ensure server is running first
- Check firewall settings

**"HMAC verification failed"**
- Verify correct master key is used
- Check client_id matches server configuration

**"Round mismatch"**
- Protocol state desynchronized
- Restart both client and server

**"Invalid message format"**
- Network corruption or attack detected
- Session terminated for safety
