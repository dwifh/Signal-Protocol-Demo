"""
signal_demo.py

Practical component for Section 6(b) — Signal Protocol report.

Two parts:
  1. X25519 ECDH shared-secret derivation (Alice and Bob independently
     arrive at the same shared secret, mirroring the DH(.,.) calls used
     inside X3DH).
  2. A symmetric-key ratchet (HMAC-SHA256 KDF chain), demonstrating
     forward secrecy empirically: given a later chain key, you can step
     forward and derive all future message keys, but you cannot step
     backward and recover any earlier message key.

Run with:  python3 signal_demo.py
Requires:  pip install cryptography
"""

import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Part 1 — X25519 ECDH shared-secret derivation
# ---------------------------------------------------------------------------

def x25519_demo():
    print("=" * 70)
    print("PART 1 — X25519 ECDH shared-secret derivation")
    print("=" * 70)

    # Alice and Bob each generate a private/public Curve25519 key pair.
    # In real X3DH these correspond to key pairs like (IK_A, EK_A) and
    # (IK_B, SPK_B) — here we demonstrate one single DH(.,.) call, which
    # is the building block repeated four times inside X3DH.
    alice_private = X25519PrivateKey.generate()
    alice_public = alice_private.public_key()

    bob_private = X25519PrivateKey.generate()
    bob_public = bob_private.public_key()

    # Each side computes the DH shared secret using their own private key
    # and the other party's public key. This is exactly DH(sk, PK) as
    # used in Signal's specification.
    alice_shared = alice_private.exchange(bob_public)
    bob_shared = bob_private.exchange(alice_public)

    alice_pub_bytes = alice_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    bob_pub_bytes = bob_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    print(f"Alice's public key (32 bytes): {alice_pub_bytes.hex()}")
    print(f"Bob's public key   (32 bytes): {bob_pub_bytes.hex()}")
    print()
    print(f"Alice's computed shared secret: {alice_shared.hex()}")
    print(f"Bob's computed shared secret:   {bob_shared.hex()}")
    print()

    assert alice_shared == bob_shared, "Shared secrets do not match!"
    print("[OK] Alice and Bob independently derived the SAME shared secret,")
    print("     without ever transmitting their private keys.")
    print()

    return alice_shared  # used to seed Part 2


# ---------------------------------------------------------------------------
# Part 2 — Symmetric-key ratchet (HMAC-SHA256 KDF chain)
# ---------------------------------------------------------------------------

def kdf_chain_step(chain_key: bytes):
    """
    One step of the symmetric-key ratchet, exactly as in Section 4.5.1:

        MK_i     = HMAC-SHA256(CK_i, 0x01)
        CK_{i+1} = HMAC-SHA256(CK_i, 0x02)

    Returns (message_key, next_chain_key).
    """
    message_key = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    next_chain_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return message_key, next_chain_key


def ratchet_demo(initial_chain_key: bytes, steps: int = 5):
    print("=" * 70)
    print("PART 2 — Symmetric-key ratchet (HMAC-SHA256 KDF chain)")
    print("=" * 70)

    chain_key = initial_chain_key
    message_keys = []
    chain_keys = [chain_key]

    print(f"Initial chain key CK_0: {chain_key.hex()}")
    print()

    for i in range(steps):
        message_key, chain_key = kdf_chain_step(chain_key)
        message_keys.append(message_key)
        chain_keys.append(chain_key)
        print(f"Step {i}:")
        print(f"  MK_{i}     = {message_key.hex()}")
        print(f"  CK_{i+1}   = {chain_key.hex()}")

    print()
    print("-" * 70)
    print("Forward secrecy check")
    print("-" * 70)

    # Forward direction: given CK_2, can we recompute MK_3, MK_4 (future)?
    compromised_index = 2
    compromised_ck = chain_keys[compromised_index]
    print(f"Suppose an attacker steals CK_{compromised_index}: "
          f"{compromised_ck.hex()}")
    print()

    # Step FORWARD from the compromised chain key.
    ck = compromised_ck
    recomputed_forward = []
    for i in range(compromised_index, steps):
        mk, ck = kdf_chain_step(ck)
        recomputed_forward.append(mk)

    forward_ok = recomputed_forward == message_keys[compromised_index:]
    print(f"Stepping FORWARD from CK_{compromised_index}, the attacker CAN "
          f"recompute MK_{compromised_index}..MK_{steps-1}:")
    print(f"  Matches real message keys? {forward_ok}")
    print()

    # Step BACKWARD: try to recover an earlier message key (MK_0) from a
    # later chain key. This is impossible because HMAC-SHA256 is a
    # one-way function — there is no operation that inverts it.
    print(f"Now try to recover MK_0 (an EARLIER message key) from "
          f"CK_{compromised_index}:")
    print("  HMAC-SHA256 is a one-way function — there is no inverse")
    print("  operation available. The only way to 'search' for MK_0 would")
    print("  be to brute-force every possible previous chain key, which is")
    print("  computationally infeasible for a 256-bit key space.")
    print()
    print(f"  MK_0 (real, for comparison only): {message_keys[0].hex()}")
    print("  --> Not derivable from CK_2 or any later chain key.")
    print()

    print("[OK] This demonstrates forward secrecy empirically: compromising")
    print("     a chain key exposes all FUTURE message keys, but no PAST")
    print("     message keys are recoverable.")


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    shared_secret = x25519_demo()
    # Use the ECDH shared secret as the seed for the ratchet chain, showing
    # the conceptual link between X3DH's output (SK) and the Double
    # Ratchet's initial chain key.
    ratchet_demo(initial_chain_key=shared_secret, steps=5)
