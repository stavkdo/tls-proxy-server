"""TLS 1.3 key schedule (RFC 8446 S7.1) and record protection (RFC 8446 S5.2/5.3).

Peer-role-agnostic: used today by the client-role handshake in `tls_probe.py`
(proxy -> target), and intended for reuse by a future server-role handshake
(browser -> proxy).

Only the pieces our handshake actually needs are implemented: no PSK/resumption,
no 0-RTT, no key updates. The negotiated cipher suite throughout this project
is `TLS_AES_256_GCM_SHA384` (AES-256-GCM record protection, SHA-384 transcript
hash/HKDF) -- chosen over the more common AES_128_GCM_SHA256 for the larger
quantum security margin: Grover's algorithm roughly halves effective symmetric
key strength against a quantum attacker, so AES-128 drops to ~64-bit quantum
security while AES-256 holds at ~128-bit.
"""

import hashlib
import struct

from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

SHA384 = hashes.SHA384()


def hkdf_extract(salt: bytes, ikm: bytes, hash_algo) -> bytes:
    """RFC 5869 HKDF-Extract: PRK = HMAC-Hash(salt, IKM)."""
    h = crypto_hmac.HMAC(salt, hash_algo)
    h.update(ikm)
    return h.finalize()


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_algo) -> bytes:
    """RFC 5869 HKDF-Expand, via the audited library primitive."""
    return HKDFExpand(algorithm=hash_algo, length=length, info=info).derive(prk)


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int, hash_algo) -> bytes:
    """RFC 8446 S7.1 HKDF-Expand-Label."""
    full_label = b"tls13 " + label
    if not (0 < len(full_label) <= 255):
        raise ValueError("label out of range")
    if len(context) > 255:
        raise ValueError("context out of range")
    hkdf_label = (
        struct.pack(">H", length)
        + bytes([len(full_label)]) + full_label
        + bytes([len(context)]) + context
    )
    return hkdf_expand(secret, hkdf_label, length, hash_algo)


def derive_secret(secret: bytes, label: bytes, transcript_hash_value: bytes, hash_algo) -> bytes:
    """RFC 8446 S7.1 Derive-Secret(Secret, Label, Messages) -- `transcript_hash_value`
    is Transcript-Hash(Messages), already computed by the caller."""
    return hkdf_expand_label(secret, label, transcript_hash_value, hash_algo.digest_size, hash_algo)


def empty_hash(hash_algo) -> bytes:
    """Transcript-Hash("") -- the hash of zero bytes of input, used for the
    two 'derived' chaining steps. Not to be confused with a zero-filled digest."""
    return hashlib.new(hash_algo.name).digest()


class TranscriptHash:
    """Running hash over handshake messages, in the order they're sent/received."""

    def __init__(self, hash_algo=SHA384):
        self._hash_algo = hash_algo
        self._h = hashlib.new(hash_algo.name)

    def update(self, handshake_message_bytes: bytes) -> None:
        self._h.update(handshake_message_bytes)

    def digest(self) -> bytes:
        return self._h.digest()


class KeySchedule:
    """RFC 8446 S7.1 key schedule, PSK-less ((EC)DHE-only) path."""

    def __init__(self, hash_algo=SHA384):
        self.hash_algo = hash_algo
        zero = b"\x00" * hash_algo.digest_size
        self.early_secret = hkdf_extract(zero, zero, hash_algo)
        self._derived_early = derive_secret(self.early_secret, b"derived", empty_hash(hash_algo), hash_algo)
        self.handshake_secret = None
        self.master_secret = None

    def handshake_traffic_secrets(self, shared_secret: bytes, transcript_hash_at_server_hello: bytes):
        """Returns (client_handshake_traffic_secret, server_handshake_traffic_secret)."""
        self.handshake_secret = hkdf_extract(self._derived_early, shared_secret, self.hash_algo)
        client_hs = derive_secret(
            self.handshake_secret, b"c hs traffic", transcript_hash_at_server_hello, self.hash_algo
        )
        server_hs = derive_secret(
            self.handshake_secret, b"s hs traffic", transcript_hash_at_server_hello, self.hash_algo
        )
        return client_hs, server_hs

    def application_traffic_secrets(self, transcript_hash_at_server_finished: bytes):
        """Returns (client_application_traffic_secret_0, server_application_traffic_secret_0)."""
        zero = b"\x00" * self.hash_algo.digest_size
        derived_hs = derive_secret(self.handshake_secret, b"derived", empty_hash(self.hash_algo), self.hash_algo)
        self.master_secret = hkdf_extract(derived_hs, zero, self.hash_algo)
        client_ap = derive_secret(
            self.master_secret, b"c ap traffic", transcript_hash_at_server_finished, self.hash_algo
        )
        server_ap = derive_secret(
            self.master_secret, b"s ap traffic", transcript_hash_at_server_finished, self.hash_algo
        )
        return client_ap, server_ap


def finished_verify_data(traffic_secret: bytes, transcript_hash_value: bytes, hash_algo=SHA384) -> bytes:
    """RFC 8446 S4.4.4: verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, ...))."""
    finished_key = hkdf_expand_label(traffic_secret, b"finished", b"", hash_algo.digest_size, hash_algo)
    h = crypto_hmac.HMAC(finished_key, hash_algo)
    h.update(transcript_hash_value)
    return h.finalize()


_RECORD_CONTENT_TYPE_APPLICATION_DATA = 0x17
_RECORD_LEGACY_VERSION = b"\x03\x03"
_GCM_TAG_LEN = 16


class RecordProtector:
    """AES-256-GCM TLS 1.3 record protection (RFC 8446 S5.2/5.3) for one
    direction of one epoch (handshake or application). A fresh instance is
    needed per direction and per epoch -- sequence numbers are per-instance
    and never reset."""

    def __init__(self, traffic_secret: bytes, hash_algo=SHA384, key_length: int = 32):
        key = hkdf_expand_label(traffic_secret, b"key", b"", key_length, hash_algo)
        self._iv = hkdf_expand_label(traffic_secret, b"iv", b"", 12, hash_algo)
        self._aead = AESGCM(key)
        self._seq = 0

    def _next_nonce(self) -> bytes:
        seq_bytes = self._seq.to_bytes(len(self._iv), "big")
        nonce = bytes(a ^ b for a, b in zip(self._iv, seq_bytes))
        self._seq += 1
        return nonce

    def seal(self, plaintext: bytes, content_type: int) -> bytes:
        inner_plaintext = plaintext + bytes([content_type])
        record_len = len(inner_plaintext) + _GCM_TAG_LEN
        header = bytes([_RECORD_CONTENT_TYPE_APPLICATION_DATA]) + _RECORD_LEGACY_VERSION + struct.pack(">H", record_len)
        ciphertext = self._aead.encrypt(self._next_nonce(), inner_plaintext, header)
        return header + ciphertext

    def open(self, record: bytes):
        """`record` is a complete TLSCiphertext record (header + ciphertext+tag).
        Returns (content, content_type). Raises on authentication failure
        (tampered/forged record) via cryptography's InvalidTag."""
        header, ciphertext = record[:5], record[5:]
        inner_plaintext = self._aead.decrypt(self._next_nonce(), ciphertext, header)

        i = len(inner_plaintext) - 1
        while i >= 0 and inner_plaintext[i] == 0:
            i -= 1
        if i < 0:
            raise ValueError("inner plaintext has no content type (all-zero padding)")
        return inner_plaintext[:i], inner_plaintext[i]
