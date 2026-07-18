# Signal Protocol Demo — X25519 ECDH + Symmetric-Key Ratchet

Practical component accompanying Section (Mathematical and Practical
Implementation) of the CS2572 Assessment 2 report on the Signal Protocol.

This demo implements, in real Curve25519 arithmetic (via Python's
`cryptography` library), the two core mechanisms derived mathematically in
the report:

1. **X25519 ECDH** — Alice and Bob each generate a Curve25519 key pair and
   independently derive the same shared secret, mirroring the `DH(·,·)`
   calls used inside X3DH.
2. **Symmetric-key ratchet (HMAC-SHA256 KDF chain)** — the shared secret
   seeds a chain of message keys, exactly as described in Section 4.5.1.
   The script then demonstrates **forward secrecy empirically**: given a
   chain key, you can always step *forward* to derive future message keys,
   but there is no way to step *backward* and recover an earlier one.

## Requirements

- Python 3.8+
- `cryptography` library

## Setup

```bash
git clone <https://github.com/dwifh/Signal-Protocol-Demo>
cd signal-demo
pip install -r requirements.txt
```

## Run

```bash
python3 signal_demo.py
```

## What the output shows

- Part 1 prints Alice's and Bob's public keys and their independently
  computed shared secrets, then asserts they are equal.
- Part 2 prints five steps of the KDF chain (`CK_0` → `CK_5`, with a
  `MK_i` produced at each step), then:
  - "compromises" `CK_2` and shows that all **future** message keys
    (`MK_2`, `MK_3`, `MK_4`) can be recomputed forward from it, and
  - explains why `MK_0` (an **earlier** message key) cannot be recovered
    from `CK_2`, since HMAC-SHA256 has no inverse operation.

This is the empirical demonstration referenced in the report: forward
secrecy is not an assumption, it falls directly out of HMAC's one-wayness.

## Relationship to the report's maths

| Report section | Demo code |
|---|---|
| (X3DH four DH terms) | `x25519_demo()` — single `DH(·,·)` call, the building block repeated four times in real X3DH |
| (Symmetric-key ratchet formula) | `kdf_chain_step()` — implements `MK_i = HMAC-SHA256(CK_i, 0x01)`, `CK_{i+1} = HMAC-SHA256(CK_i, 0x02)` exactly |
| (why forward secrecy holds) | `ratchet_demo()` — empirically shows the forward-only property |

Note: this demo implements one DH call and the symmetric ratchet only. It
does not implement the full four-DH X3DH handshake, the DH ratchet, or
PQXDH.
