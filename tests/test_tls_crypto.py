"""Known-answer tests (RFC 8448 S3) for the key-schedule primitives, plus
behavioral tests for AEAD record protection.

RFC 8448's published trace uses TLS_AES_128_GCM_SHA256 (SHA-256), while this
project's real engine uses TLS_AES_256_GCM_SHA384 (SHA-384). hkdf_expand_label
/ derive_secret / hkdf_extract are hash-algorithm-agnostic -- the hash is just
a parameter -- so these tests validate the algorithm itself against SHA-256
known-answer vectors; the same (unmodified) functions are then used with
SHA-384 in the real engine. RecordProtector's AES-256-GCM behavior is tested
separately below without needing an external oracle value.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
import pytest

import tls_crypto

SHA256 = hashes.SHA256()


def _hex(s):
    return bytes.fromhex(s.replace("\n", " "))


# --- RFC 8448 S3 "Simple 1-RTT Handshake" known-answer values ---

CLIENT_HELLO = _hex("""
01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a
8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00
91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14
00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00
33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe
b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d
00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02
01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01
""")

SERVER_HELLO = _hex("""
02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a
c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d
00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d
f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04
""")

ECDHE_SHARED_SECRET = _hex(
    "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d"
    "35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d"
)

EXPECTED_EARLY_SECRET = _hex(
    "33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2"
    "10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a"
)

EXPECTED_HANDSHAKE_SECRET = _hex(
    "1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01"
    "04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac"
)

EXPECTED_CLIENT_HS_TRAFFIC_SECRET = _hex(
    "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f"
    "3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21"
)

EXPECTED_SERVER_HS_TRAFFIC_SECRET = _hex(
    "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4"
    "e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"
)

EXPECTED_MASTER_SECRET = _hex(
    "18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47"
    "80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19"
)


def test_rfc8448_early_secret():
    zero = b"\x00" * 32
    early_secret = tls_crypto.hkdf_extract(zero, zero, SHA256)
    assert early_secret == EXPECTED_EARLY_SECRET


def test_rfc8448_handshake_secret_and_traffic_secrets():
    zero = b"\x00" * 32
    early_secret = tls_crypto.hkdf_extract(zero, zero, SHA256)
    derived_early = tls_crypto.derive_secret(
        early_secret, b"derived", tls_crypto.empty_hash(SHA256), SHA256
    )
    handshake_secret = tls_crypto.hkdf_extract(derived_early, ECDHE_SHARED_SECRET, SHA256)
    assert handshake_secret == EXPECTED_HANDSHAKE_SECRET

    transcript_hash = tls_crypto.TranscriptHash(SHA256)
    transcript_hash.update(CLIENT_HELLO)
    transcript_hash.update(SERVER_HELLO)
    th = transcript_hash.digest()

    client_hs = tls_crypto.derive_secret(handshake_secret, b"c hs traffic", th, SHA256)
    server_hs = tls_crypto.derive_secret(handshake_secret, b"s hs traffic", th, SHA256)
    assert client_hs == EXPECTED_CLIENT_HS_TRAFFIC_SECRET
    assert server_hs == EXPECTED_SERVER_HS_TRAFFIC_SECRET


def test_rfc8448_master_secret():
    zero = b"\x00" * 32
    early_secret = tls_crypto.hkdf_extract(zero, zero, SHA256)
    derived_early = tls_crypto.derive_secret(
        early_secret, b"derived", tls_crypto.empty_hash(SHA256), SHA256
    )
    handshake_secret = tls_crypto.hkdf_extract(derived_early, ECDHE_SHARED_SECRET, SHA256)

    derived_hs = tls_crypto.derive_secret(
        handshake_secret, b"derived", tls_crypto.empty_hash(SHA256), SHA256
    )
    master_secret = tls_crypto.hkdf_extract(derived_hs, zero, SHA256)
    assert master_secret == EXPECTED_MASTER_SECRET


def test_key_schedule_matches_manual_derivation_end_to_end():
    """The KeySchedule class wraps the same primitives tested above -- check
    it reproduces the RFC vectors too, not just the free functions."""
    schedule = tls_crypto.KeySchedule(SHA256)
    assert schedule.early_secret == EXPECTED_EARLY_SECRET

    transcript_hash = tls_crypto.TranscriptHash(SHA256)
    transcript_hash.update(CLIENT_HELLO)
    transcript_hash.update(SERVER_HELLO)

    client_hs, server_hs = schedule.handshake_traffic_secrets(
        ECDHE_SHARED_SECRET, transcript_hash.digest()
    )
    assert schedule.handshake_secret == EXPECTED_HANDSHAKE_SECRET
    assert client_hs == EXPECTED_CLIENT_HS_TRAFFIC_SECRET
    assert server_hs == EXPECTED_SERVER_HS_TRAFFIC_SECRET


# --- RecordProtector (AES-256-GCM) behavioral tests ---

def test_record_protector_round_trip():
    secret = b"\x11" * 48  # SHA-384 digest-sized traffic secret
    sealer = tls_crypto.RecordProtector(secret)
    opener = tls_crypto.RecordProtector(secret)

    record = sealer.seal(b"hello world", content_type=0x17)
    content, content_type = opener.open(record)

    assert content == b"hello world"
    assert content_type == 0x17


def test_record_protector_sequence_number_changes_ciphertext():
    secret = b"\x22" * 48
    sealer = tls_crypto.RecordProtector(secret)

    record1 = sealer.seal(b"same plaintext", content_type=0x17)
    record2 = sealer.seal(b"same plaintext", content_type=0x17)

    assert record1 != record2  # different nonce (seq 0 vs 1) -> different ciphertext


def test_record_protector_rejects_tampered_ciphertext():
    secret = b"\x33" * 48
    sealer = tls_crypto.RecordProtector(secret)
    opener = tls_crypto.RecordProtector(secret)

    record = bytearray(sealer.seal(b"integrity matters", content_type=0x17))
    record[-1] ^= 0x01  # flip a bit in the GCM tag

    with pytest.raises(InvalidTag):
        opener.open(bytes(record))


def test_record_protector_independent_sequence_per_direction():
    secret_a = b"\x44" * 48
    secret_b = b"\x55" * 48

    client_write = tls_crypto.RecordProtector(secret_a)
    server_write = tls_crypto.RecordProtector(secret_b)

    # Both start at sequence 0 independently -- sealing on one side doesn't
    # affect the other's sequence counter.
    r1 = client_write.seal(b"from client", content_type=0x17)
    r2 = server_write.seal(b"from server", content_type=0x17)

    client_read = tls_crypto.RecordProtector(secret_a)
    server_read = tls_crypto.RecordProtector(secret_b)
    assert client_read.open(r1) == (b"from client", 0x17)
    assert server_read.open(r2) == (b"from server", 0x17)
