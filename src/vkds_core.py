"""
VKDS core implementation for privacy-preserving PHR encryption.

This module implements the main algorithmic components required by the
VKDS reproducibility package:

1. Diffie-Hellman based shared secret generation
2. QKD-inspired deterministic quantum key derivation
3. Non-Abelian group inspired keystream transformation
4. Fragment-level encryption/decryption
5. Hash-based signature generation and verification
6. Trust-score computation for reproducibility experiments

The implementation is intended for research reproducibility using synthetic
PHR data. It is not a production clinical cryptography library.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


# RFC 3526 2048-bit MODP Group prime.
# Used as a stable Diffie-Hellman modulus for deterministic reproducibility.
RFC3526_2048_PRIME_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
"""


def _clean_hex(value: str) -> str:
    return "".join(value.split())


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _int_to_bytes(value: int, length: Optional[int] = None) -> bytes:
    if value < 0:
        raise ValueError("Only non-negative integers can be converted to bytes.")
    needed = max(1, (value.bit_length() + 7) // 8)
    if length is None:
        length = needed
    return value.to_bytes(length, byteorder="big")


def _bytes_to_int(value: bytes) -> int:
    return int.from_bytes(value, byteorder="big")


def _stable_seed_bytes(seed: int, label: str, length: int = 32) -> bytes:
    output = b""
    counter = 0
    seed_material = f"{seed}:{label}".encode("utf-8")
    while len(output) < length:
        output += _sha256(seed_material + counter.to_bytes(4, "big"))
        counter += 1
    return output[:length]


def _expand_keystream(seed: bytes, length: int, context: bytes = b"") -> bytes:
    """Expand a seed into a deterministic byte stream using SHA-256 counter mode."""
    if length < 0:
        raise ValueError("length must be non-negative")
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        block = _sha256(seed + context + counter.to_bytes(8, "big"))
        stream.extend(block)
        counter += 1
    return bytes(stream[:length])


def split_fragments(payload: bytes, fragment_size: int) -> List[bytes]:
    """Split byte payload into fixed-size fragments."""
    if fragment_size <= 0:
        raise ValueError("fragment_size must be positive")
    return [payload[i : i + fragment_size] for i in range(0, len(payload), fragment_size)]


def combine_fragments(fragments: Sequence[bytes]) -> bytes:
    return b"".join(fragments)


def constant_time_equal(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(left, right)


@dataclass
class VKDSRuntimeConfig:
    """Runtime parameters for the VKDS core."""

    random_seed: int = 42
    fragment_size_bytes: int = 512
    qkd_key_length_bits: int = 256
    qkd_iterations: int = 30
    qkd_error_threshold: float = 0.11
    dh_generator: int = 2
    dh_private_key_bits: int = 256
    non_abelian_prime: int = 257
    non_abelian_rounds: int = 8
    hash_algorithm: str = "sha256"
    initial_trust_score: float = 0.70
    valid_signature_weight: float = 0.10
    reconstruction_weight: float = 0.05
    qkd_consistency_weight: float = 0.05
    policy_verification_weight: float = 0.05

    @classmethod
    def from_dict(cls, cfg: Dict[str, Any]) -> "VKDSRuntimeConfig":
        project = cfg.get("project", {})
        experiment = cfg.get("experiment", {})
        qkd = cfg.get("qkd", {})
        dh = cfg.get("diffie_hellman", {})
        nae = cfg.get("non_abelian_encryption", {})
        trust = cfg.get("trust_evaluation", {})
        signature = cfg.get("signature", {})

        return cls(
            random_seed=int(project.get("random_seed", 42)),
            fragment_size_bytes=int(experiment.get("fragment_size_bytes", 512)),
            qkd_key_length_bits=int(qkd.get("key_length_bits", 256)),
            qkd_iterations=int(qkd.get("iterations", 30)),
            qkd_error_threshold=float(qkd.get("error_threshold", 0.11)),
            dh_generator=int(dh.get("generator", 2)),
            dh_private_key_bits=int(dh.get("private_key_bits", 256)),
            non_abelian_prime=int(nae.get("group_order_prime", 257)),
            non_abelian_rounds=int(nae.get("transformation_rounds", 8)),
            hash_algorithm=str(signature.get("hash_algorithm", "sha256")),
            initial_trust_score=float(trust.get("initial_trust_score", 0.70)),
            valid_signature_weight=float(trust.get("valid_signature_weight", 0.10)),
            reconstruction_weight=float(trust.get("reconstruction_weight", 0.05)),
            qkd_consistency_weight=float(trust.get("qkd_consistency_weight", 0.05)),
            policy_verification_weight=float(trust.get("policy_verification_weight", 0.05)),
        )


@dataclass
class DiffieHellmanMaterial:
    prime: int
    generator: int
    admin_private: int
    user_private: int
    admin_public: int
    user_public: int
    shared_secret_admin: int
    shared_secret_user: int

    @property
    def is_valid(self) -> bool:
        return self.shared_secret_admin == self.shared_secret_user

    @property
    def shared_secret(self) -> int:
        if not self.is_valid:
            raise ValueError("Diffie-Hellman shared secret mismatch.")
        return self.shared_secret_admin


@dataclass
class QKDMaterial:
    raw_key: bytes
    matched_indices: List[int]
    sender_bits: List[int]
    receiver_bits: List[int]
    sender_bases: List[int]
    receiver_bases: List[int]
    estimated_error_rate: float
    accepted: bool

    @property
    def key_hex(self) -> str:
        return self.raw_key.hex()


@dataclass
class EncryptedFragment:
    index: int
    original_length: int
    nonce: bytes
    ciphertext: bytes
    signature: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "original_length": self.original_length,
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "signature": base64.b64encode(self.signature).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, item: Dict[str, Any]) -> "EncryptedFragment":
        return cls(
            index=int(item["index"]),
            original_length=int(item["original_length"]),
            nonce=base64.b64decode(item["nonce"]),
            ciphertext=base64.b64decode(item["ciphertext"]),
            signature=base64.b64decode(item["signature"]),
        )


@dataclass
class EncryptionBundle:
    fragments: List[EncryptedFragment]
    metadata: Dict[str, Any]
    qkd_key_digest: str
    dh_secret_digest: str
    payload_digest: str

    def to_json(self, indent: int = 2) -> str:
        payload = {
            "metadata": self.metadata,
            "qkd_key_digest": self.qkd_key_digest,
            "dh_secret_digest": self.dh_secret_digest,
            "payload_digest": self.payload_digest,
            "fragments": [fragment.to_dict() for fragment in self.fragments],
        }
        return json.dumps(payload, indent=indent)

    @classmethod
    def from_json(cls, value: str) -> "EncryptionBundle":
        payload = json.loads(value)
        return cls(
            metadata=dict(payload["metadata"]),
            qkd_key_digest=str(payload["qkd_key_digest"]),
            dh_secret_digest=str(payload["dh_secret_digest"]),
            payload_digest=str(payload["payload_digest"]),
            fragments=[EncryptedFragment.from_dict(item) for item in payload["fragments"]],
        )


@dataclass
class VKDSProfile:
    key_generation_time: float
    encryption_time: float
    decryption_time: float
    computation_time: float
    signature_valid: bool
    reconstruction_valid: bool
    qkd_accepted: bool
    policy_verified: bool
    trust_score: float
    number_of_fragments: int
    payload_size_bytes: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_generation_time": self.key_generation_time,
            "encryption_time": self.encryption_time,
            "decryption_time": self.decryption_time,
            "computation_time": self.computation_time,
            "signature_valid": self.signature_valid,
            "reconstruction_valid": self.reconstruction_valid,
            "qkd_accepted": self.qkd_accepted,
            "policy_verified": self.policy_verified,
            "trust_score": self.trust_score,
            "number_of_fragments": self.number_of_fragments,
            "payload_size_bytes": self.payload_size_bytes,
        }


class DiffieHellmanSecretGenerator:
    """Deterministic Diffie-Hellman generator for reproducible experiments."""

    def __init__(self, config: VKDSRuntimeConfig):
        self.config = config
        self.prime = int(_clean_hex(RFC3526_2048_PRIME_HEX), 16)
        self.generator = config.dh_generator

    def _private_key(self, label: str) -> int:
        length = max(32, self.config.dh_private_key_bits // 8)
        seed = _stable_seed_bytes(self.config.random_seed, f"dh:{label}", length)
        key = _bytes_to_int(seed)
        lower_bound = 2
        upper_bound = self.prime - 2
        return lower_bound + (key % (upper_bound - lower_bound))

    def generate(self, user_label: str = "registered_user") -> DiffieHellmanMaterial:
        admin_private = self._private_key("admin")
        user_private = self._private_key(user_label)

        admin_public = pow(self.generator, admin_private, self.prime)
        user_public = pow(self.generator, user_private, self.prime)

        shared_secret_admin = pow(user_public, admin_private, self.prime)
        shared_secret_user = pow(admin_public, user_private, self.prime)

        return DiffieHellmanMaterial(
            prime=self.prime,
            generator=self.generator,
            admin_private=admin_private,
            user_private=user_private,
            admin_public=admin_public,
            user_public=user_public,
            shared_secret_admin=shared_secret_admin,
            shared_secret_user=shared_secret_user,
        )


class QKDKeyGenerator:
    """QKD-inspired key-generation simulator.

    The simulator models sender bits, receiver measurements, basis matching,
    simple error estimation, and key derivation. Fixed seeds make the procedure
    reproducible for the manuscript benchmark pipeline.
    """

    def __init__(self, config: VKDSRuntimeConfig):
        self.config = config

    def generate(self, context: str = "default") -> QKDMaterial:
        rng_seed = _bytes_to_int(_stable_seed_bytes(self.config.random_seed, f"qkd:{context}", 16))
        rng = random.Random(rng_seed)

        sequence_length = max(self.config.qkd_key_length_bits * 4, 512)
        sender_bits = [rng.randint(0, 1) for _ in range(sequence_length)]
        sender_bases = [rng.randint(0, 1) for _ in range(sequence_length)]
        receiver_bases = [rng.randint(0, 1) for _ in range(sequence_length)]

        receiver_bits: List[int] = []
        for bit, sb, rb in zip(sender_bits, sender_bases, receiver_bases):
            if sb == rb:
                receiver_bits.append(bit)
            else:
                receiver_bits.append(rng.randint(0, 1))

        # Quantum rotation inspired refinement. It introduces controlled basis
        # convergence without making the process non-deterministic.
        for iteration in range(self.config.qkd_iterations):
            position = (iteration * 17 + rng.randint(0, sequence_length - 1)) % sequence_length
            if sender_bases[position] != receiver_bases[position]:
                if rng.random() > 0.35:
                    receiver_bases[position] = sender_bases[position]
                    receiver_bits[position] = sender_bits[position]

        matched_indices = [
            idx for idx, (sb, rb) in enumerate(zip(sender_bases, receiver_bases)) if sb == rb
        ]

        if len(matched_indices) < self.config.qkd_key_length_bits:
            # Deterministic fallback: extend candidate pool using strongest
            # pseudo-randomly selected positions.
            remaining = [idx for idx in range(sequence_length) if idx not in matched_indices]
            rng.shuffle(remaining)
            matched_indices.extend(remaining[: self.config.qkd_key_length_bits - len(matched_indices)])

        sampled = matched_indices[: min(64, len(matched_indices))]
        if sampled:
            mismatches = sum(1 for idx in sampled if sender_bits[idx] != receiver_bits[idx])
            estimated_error_rate = mismatches / len(sampled)
        else:
            estimated_error_rate = 1.0

        accepted = estimated_error_rate <= self.config.qkd_error_threshold

        key_bits = [receiver_bits[idx] for idx in matched_indices[: self.config.qkd_key_length_bits]]
        while len(key_bits) < self.config.qkd_key_length_bits:
            key_bits.append(rng.randint(0, 1))

        key_bytes = bytearray()
        for offset in range(0, len(key_bits), 8):
            byte = 0
            for bit in key_bits[offset : offset + 8]:
                byte = (byte << 1) | int(bit)
            key_bytes.append(byte)

        raw_key = _sha256(bytes(key_bytes) + context.encode("utf-8"))

        return QKDMaterial(
            raw_key=raw_key,
            matched_indices=matched_indices[: self.config.qkd_key_length_bits],
            sender_bits=sender_bits,
            receiver_bits=receiver_bits,
            sender_bases=sender_bases,
            receiver_bases=receiver_bases,
            estimated_error_rate=estimated_error_rate,
            accepted=accepted,
        )


class NonAbelianKeystream:
    """Non-Abelian group inspired deterministic keystream generator.

    The module uses 2x2 matrices over a finite field. Matrix multiplication is
    generally non-commutative, which provides a compact reproducible model for
    the NAE stage described in the manuscript.
    """

    def __init__(self, config: VKDSRuntimeConfig):
        self.config = config
        self.p = int(config.non_abelian_prime)
        if self.p <= 2:
            raise ValueError("non_abelian_prime must be greater than 2")

    def _matrix_from_seed(self, seed: bytes, salt: bytes) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        digest = _expand_keystream(seed, 16, salt)
        values = [b % self.p for b in digest[:4]]

        # Use triangular-like invertible matrices. Ensure determinant is non-zero.
        a = values[0] or 1
        b = values[1]
        c = values[2]
        d = values[3] or 1

        if ((a * d - b * c) % self.p) == 0:
            d = (d + 1) % self.p or 1

        return ((a, b), (c, d))

    def _mul(
        self,
        left: Tuple[Tuple[int, int], Tuple[int, int]],
        right: Tuple[Tuple[int, int], Tuple[int, int]],
    ) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        p = self.p
        return (
            (
                (left[0][0] * right[0][0] + left[0][1] * right[1][0]) % p,
                (left[0][0] * right[0][1] + left[0][1] * right[1][1]) % p,
            ),
            (
                (left[1][0] * right[0][0] + left[1][1] * right[1][0]) % p,
                (left[1][0] * right[0][1] + left[1][1] * right[1][1]) % p,
            ),
        )

    def _det(self, matrix: Tuple[Tuple[int, int], Tuple[int, int]]) -> int:
        return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % self.p

    def _inv(self, matrix: Tuple[Tuple[int, int], Tuple[int, int]]) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        det = self._det(matrix)
        if det == 0:
            raise ValueError("Matrix is not invertible in the finite field.")
        inv_det = pow(det, -1, self.p)
        return (
            ((matrix[1][1] * inv_det) % self.p, (-matrix[0][1] * inv_det) % self.p),
            ((-matrix[1][0] * inv_det) % self.p, (matrix[0][0] * inv_det) % self.p),
        )

    def _matrix_bytes(self, matrix: Tuple[Tuple[int, int], Tuple[int, int]]) -> bytes:
        width = max(2, math.ceil(self.p.bit_length() / 8))
        return b"".join(_int_to_bytes(item, width) for row in matrix for item in row)

    def seed_for_fragment(
        self,
        quantum_key: bytes,
        shared_secret: int,
        fragment_index: int,
        nonce: bytes,
    ) -> bytes:
        secret_bytes = _int_to_bytes(shared_secret)
        base_seed = _sha256(quantum_key + secret_bytes + nonce + fragment_index.to_bytes(8, "big"))

        x = self._matrix_from_seed(base_seed, b"subgroup-x")
        y = self._matrix_from_seed(base_seed, b"subgroup-y")

        # Non-commutative commutator: X * Y * X^-1 * Y^-1
        commutator = self._mul(self._mul(self._mul(x, y), self._inv(x)), self._inv(y))

        state = self._matrix_bytes(commutator)
        for round_idx in range(self.config.non_abelian_rounds):
            salt = b"nae-round-" + round_idx.to_bytes(2, "big")
            left = self._matrix_from_seed(_sha256(state + base_seed), salt + b"L")
            right = self._matrix_from_seed(_sha256(base_seed + state), salt + b"R")
            # Preserve non-commutative ordering.
            mixed = self._mul(self._mul(left, commutator), right)
            state = _sha256(state + self._matrix_bytes(mixed) + salt)

        return _sha256(base_seed + state)

    def apply(
        self,
        payload: bytes,
        quantum_key: bytes,
        shared_secret: int,
        fragment_index: int,
        nonce: bytes,
    ) -> bytes:
        seed = self.seed_for_fragment(quantum_key, shared_secret, fragment_index, nonce)
        keystream = _expand_keystream(seed, len(payload), b"vkds-nae-xor")
        return bytes(byte ^ key for byte, key in zip(payload, keystream))


class VKDSCore:
    """Main VKDS workflow implementation."""

    def __init__(self, config: Optional[VKDSRuntimeConfig] = None):
        self.config = config or VKDSRuntimeConfig()
        self.dh = DiffieHellmanSecretGenerator(self.config)
        self.qkd = QKDKeyGenerator(self.config)
        self.nae = NonAbelianKeystream(self.config)

    @classmethod
    def from_config_dict(cls, cfg: Dict[str, Any]) -> "VKDSCore":
        return cls(VKDSRuntimeConfig.from_dict(cfg))

    def _signature(
        self,
        plaintext_fragment: bytes,
        ciphertext: bytes,
        quantum_key: bytes,
        shared_secret: int,
        fragment_index: int,
        nonce: bytes,
    ) -> bytes:
        secret_digest = _sha256(_int_to_bytes(shared_secret))
        message = (
            fragment_index.to_bytes(8, "big")
            + nonce
            + _sha256(plaintext_fragment)
            + _sha256(ciphertext)
        )
        return hmac.new(_sha256(quantum_key + secret_digest), message, hashlib.sha256).digest()

    def _fragment_nonce(self, payload_digest: bytes, fragment_index: int) -> bytes:
        return _sha256(
            payload_digest
            + fragment_index.to_bytes(8, "big")
            + _stable_seed_bytes(self.config.random_seed, "fragment-nonce")
        )[:16]

    def generate_key_material(self, user_label: str, context: str) -> Tuple[DiffieHellmanMaterial, QKDMaterial]:
        dh_material = self.dh.generate(user_label=user_label)
        qkd_material = self.qkd.generate(context=context)
        if not dh_material.is_valid:
            raise ValueError("Diffie-Hellman authentication failed.")
        if not qkd_material.accepted:
            raise ValueError(
                f"QKD key rejected because estimated error rate "
                f"{qkd_material.estimated_error_rate:.4f} exceeded threshold "
                f"{self.config.qkd_error_threshold:.4f}."
            )
        return dh_material, qkd_material

    def encrypt(
        self,
        payload: bytes,
        user_label: str = "registered_user",
        access_role: str = "physician",
        policy_verified: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[EncryptionBundle, DiffieHellmanMaterial, QKDMaterial, float]:
        """Encrypt a PHR payload and return an encryption bundle."""
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes-like")
        payload = bytes(payload)

        start = time.perf_counter()
        payload_digest = _sha256(payload)
        context = f"{user_label}:{access_role}:{payload_digest.hex()[:16]}"
        dh_material, qkd_material = self.generate_key_material(user_label=user_label, context=context)
        key_generation_time = time.perf_counter() - start

        fragments = split_fragments(payload, self.config.fragment_size_bytes)
        encrypted_fragments: List[EncryptedFragment] = []

        for idx, fragment in enumerate(fragments):
            nonce = self._fragment_nonce(payload_digest, idx)
            ciphertext = self.nae.apply(
                fragment,
                qkd_material.raw_key,
                dh_material.shared_secret,
                idx,
                nonce,
            )
            signature = self._signature(
                plaintext_fragment=fragment,
                ciphertext=ciphertext,
                quantum_key=qkd_material.raw_key,
                shared_secret=dh_material.shared_secret,
                fragment_index=idx,
                nonce=nonce,
            )
            encrypted_fragments.append(
                EncryptedFragment(
                    index=idx,
                    original_length=len(fragment),
                    nonce=nonce,
                    ciphertext=ciphertext,
                    signature=signature,
                )
            )

        bundle_metadata = {
            "method": "VKDS",
            "fragment_size_bytes": self.config.fragment_size_bytes,
            "number_of_fragments": len(encrypted_fragments),
            "payload_size_bytes": len(payload),
            "user_label": user_label,
            "access_role": access_role,
            "policy_verified": bool(policy_verified),
            "qkd_error_rate": qkd_material.estimated_error_rate,
        }
        if metadata:
            bundle_metadata.update(metadata)

        bundle = EncryptionBundle(
            fragments=encrypted_fragments,
            metadata=bundle_metadata,
            qkd_key_digest=_sha256(qkd_material.raw_key).hex(),
            dh_secret_digest=_sha256(_int_to_bytes(dh_material.shared_secret)).hex(),
            payload_digest=payload_digest.hex(),
        )

        return bundle, dh_material, qkd_material, key_generation_time

    def decrypt(
        self,
        bundle: EncryptionBundle,
        dh_material: DiffieHellmanMaterial,
        qkd_material: QKDMaterial,
        require_policy: bool = True,
    ) -> Tuple[bytes, bool, float]:
        """Verify and decrypt an encryption bundle."""
        start = time.perf_counter()

        if require_policy and not bool(bundle.metadata.get("policy_verified", False)):
            return b"", False, time.perf_counter() - start

        recovered_fragments: List[bytes] = []
        signature_valid = True

        for item in sorted(bundle.fragments, key=lambda fragment: fragment.index):
            plaintext = self.nae.apply(
                item.ciphertext,
                qkd_material.raw_key,
                dh_material.shared_secret,
                item.index,
                item.nonce,
            )

            plaintext = plaintext[: item.original_length]

            expected_signature = self._signature(
                plaintext_fragment=plaintext,
                ciphertext=item.ciphertext,
                quantum_key=qkd_material.raw_key,
                shared_secret=dh_material.shared_secret,
                fragment_index=item.index,
                nonce=item.nonce,
            )

            if not constant_time_equal(expected_signature, item.signature):
                signature_valid = False
                break

            recovered_fragments.append(plaintext)

        recovered = combine_fragments(recovered_fragments) if signature_valid else b""
        elapsed = time.perf_counter() - start
        return recovered, signature_valid, elapsed

    def compute_trust_score(
        self,
        signature_valid: bool,
        reconstruction_valid: bool,
        qkd_accepted: bool,
        policy_verified: bool,
    ) -> float:
        score = self.config.initial_trust_score
        if signature_valid:
            score += self.config.valid_signature_weight
        if reconstruction_valid:
            score += self.config.reconstruction_weight
        if qkd_accepted:
            score += self.config.qkd_consistency_weight
        if policy_verified:
            score += self.config.policy_verification_weight
        return round(min(1.0, max(0.0, score)), 6)

    def run_trial(
        self,
        payload: bytes,
        file_size_kb: Optional[float] = None,
        user_label: str = "registered_user",
        access_role: str = "physician",
        policy_verified: bool = True,
    ) -> Dict[str, Any]:
        """Run one complete VKDS encryption/decryption trial."""
        total_start = time.perf_counter()

        encryption_start = time.perf_counter()
        bundle, dh_material, qkd_material, key_time = self.encrypt(
            payload=payload,
            user_label=user_label,
            access_role=access_role,
            policy_verified=policy_verified,
            metadata={"file_size_kb": file_size_kb} if file_size_kb is not None else None,
        )
        encryption_time = time.perf_counter() - encryption_start

        recovered, signature_valid, decryption_time = self.decrypt(
            bundle=bundle,
            dh_material=dh_material,
            qkd_material=qkd_material,
            require_policy=True,
        )

        reconstruction_valid = constant_time_equal(payload, recovered)
        computation_time = time.perf_counter() - total_start

        trust_score = self.compute_trust_score(
            signature_valid=signature_valid,
            reconstruction_valid=reconstruction_valid,
            qkd_accepted=qkd_material.accepted,
            policy_verified=policy_verified,
        )

        profile = VKDSProfile(
            key_generation_time=key_time,
            encryption_time=encryption_time,
            decryption_time=decryption_time,
            computation_time=computation_time,
            signature_valid=signature_valid,
            reconstruction_valid=reconstruction_valid,
            qkd_accepted=qkd_material.accepted,
            policy_verified=policy_verified,
            trust_score=trust_score,
            number_of_fragments=len(bundle.fragments),
            payload_size_bytes=len(payload),
        )

        result = profile.to_dict()
        result.update(
            {
                "file_size_kb": file_size_kb if file_size_kb is not None else len(payload) / 1024,
                "qkd_error_rate": qkd_material.estimated_error_rate,
                "qkd_key_digest": bundle.qkd_key_digest,
                "dh_secret_digest": bundle.dh_secret_digest,
                "payload_digest": bundle.payload_digest,
            }
        )
        return result


def load_yaml_config(path: str) -> Dict[str, Any]:
    """Load YAML configuration.

    PyYAML is imported only when this helper is used so that the core module
    remains lightweight during direct imports.
    """
    import yaml

    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def payload_from_file(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def save_bundle(bundle: EncryptionBundle, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(bundle.to_json(indent=2))


def load_bundle(path: str) -> EncryptionBundle:
    with open(path, "r", encoding="utf-8") as handle:
        return EncryptionBundle.from_json(handle.read())


def build_core_from_yaml(path: str) -> VKDSCore:
    return VKDSCore.from_config_dict(load_yaml_config(path))


__all__ = [
    "VKDSRuntimeConfig",
    "DiffieHellmanMaterial",
    "QKDMaterial",
    "EncryptedFragment",
    "EncryptionBundle",
    "VKDSProfile",
    "DiffieHellmanSecretGenerator",
    "QKDKeyGenerator",
    "NonAbelianKeystream",
    "VKDSCore",
    "load_yaml_config",
    "payload_from_file",
    "save_bundle",
    "load_bundle",
    "build_core_from_yaml",
    "split_fragments",
    "combine_fragments",
    "constant_time_equal",
]
