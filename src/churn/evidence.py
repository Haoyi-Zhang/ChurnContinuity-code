"""Public verification of two signed, positively contradictory bindings.

No requests are sent. Deterministic signing keys below are deliberately public
fixture material and must never be used for an application. The verifier only
accepts a trusted authorization mapping, not a key supplied by the accused.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass
import hashlib
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

@dataclass(frozen=True)
class Binding:
    service: str
    epoch: int
    membership: tuple[str, ...]
    cut: int
    content: str
    attempt: str
    generation: str
    phase: str
    signer: str
    root: str

    def context(self) -> tuple:
        return (self.service, self.epoch, self.membership, self.cut, self.content,
                self.attempt, self.generation, self.phase, self.signer)

    def encode(self) -> bytes:
        return b'accountable-binding\x00' + json.dumps(asdict(self), sort_keys=True,
                 separators=(',', ':'), ensure_ascii=True).encode('ascii')

@dataclass(frozen=True)
class Signed:
    statement: Binding
    signature: bytes


def fixture_key(label: str) -> Ed25519PrivateKey:
    # A seed derivation for *public* local test fixtures, not key generation.
    seed = hashlib.sha256(('public-toy-signing-fixture:' + label).encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sign(statement: Binding, key: Ed25519PrivateKey) -> Signed:
    return Signed(statement, key.sign(statement.encode()))


def verify_contradiction(left: Signed, right: Signed, authorized: dict[tuple, bytes]) -> bool:
    a, b = left.statement, right.statement
    if a.context() != b.context() or a.root == b.root or a.phase != 'BIND':
        return False
    authorization = (a.service, a.epoch, a.membership, a.signer)
    key = authorized.get(authorization)
    if key is None or a.signer not in a.membership:
        return False
    try:
        verifier = Ed25519PublicKey.from_public_bytes(key)
        verifier.verify(left.signature, a.encode())
        verifier.verify(right.signature, b.encode())
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def export(signed: Signed) -> dict:
    return {'statement': asdict(signed.statement), 'signature_hex': signed.signature.hex()}
