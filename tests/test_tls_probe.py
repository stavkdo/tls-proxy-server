"""Tests for the hand-rolled ClientHello builder / ServerHello parser.

No live network test against a real PQC-supporting server is included here
(network-dependent, flaky in CI) -- these tests verify the wire-format
encoding/decoding and classification logic using synthetic fixtures, which
is where correctness actually matters: `probe()` itself is a thin socket
wrapper around these two functions.
"""

import struct

import tls_probe


# --- classify_group ---

def test_classify_group_known_classical():
    name, classification = tls_probe.classify_group(tls_probe.X25519)
    assert name == "x25519"
    assert classification == "classical"


def test_classify_group_known_hybrid_pqc():
    name, classification = tls_probe.classify_group(tls_probe.X25519MLKEM768)
    assert name == "X25519MLKEM768"
    assert classification == "hybrid-pqc"


def test_classify_group_unknown_defaults_to_unknown():
    name, classification = tls_probe.classify_group(0x9999)
    assert classification == "unknown"
    assert "0x9999" in name


# --- build_client_hello (round-trip / structural checks) ---

def _parse_client_hello_extensions(record: bytes):
    """Minimal independent parser used only to verify build_client_hello's
    output -- deliberately not sharing code with the encoder."""
    assert record[0] == 0x16  # handshake record
    record_len = struct.unpack_from(">H", record, 3)[0]
    handshake_msg = record[5:5 + record_len]

    assert handshake_msg[0] == 0x01  # ClientHello
    body_len = int.from_bytes(handshake_msg[1:4], "big")
    body = handshake_msg[4:4 + body_len]

    offset = 2 + 32  # legacy_version + random
    session_id_len = body[offset]
    offset += 1 + session_id_len
    cipher_suites_len = struct.unpack_from(">H", body, offset)[0]
    offset += 2 + cipher_suites_len
    compression_len = body[offset]
    offset += 1 + compression_len

    ext_total_len = struct.unpack_from(">H", body, offset)[0]
    offset += 2
    ext_end = offset + ext_total_len

    extensions = {}
    while offset < ext_end:
        ext_type, ext_len = struct.unpack_from(">HH", body, offset)
        offset += 4
        extensions[ext_type] = body[offset:offset + ext_len]
        offset += ext_len

    return extensions


def test_build_client_hello_contains_sni():
    record = tls_probe.build_client_hello("example.com", group_ids=[tls_probe.X25519])
    extensions = _parse_client_hello_extensions(record)

    sni_data = extensions[tls_probe._EXT_SERVER_NAME]
    # 2-byte list length, 1-byte name type, 2-byte hostname length, hostname
    hostname_len = struct.unpack_from(">H", sni_data, 3)[0]
    hostname = sni_data[5:5 + hostname_len].decode("ascii")
    assert hostname == "example.com"


def test_build_client_hello_offers_requested_groups_with_correct_key_share_sizes():
    group_ids = [tls_probe.X25519, tls_probe.SECP256R1, tls_probe.X25519MLKEM768]
    record = tls_probe.build_client_hello("example.com", group_ids=group_ids)
    extensions = _parse_client_hello_extensions(record)

    groups_data = extensions[tls_probe._EXT_SUPPORTED_GROUPS]
    n_groups = struct.unpack_from(">H", groups_data, 0)[0] // 2
    offered = list(struct.unpack_from(f">{n_groups}H", groups_data, 2))
    assert offered == group_ids

    key_share_data = extensions[tls_probe._EXT_KEY_SHARE]
    total_len = struct.unpack_from(">H", key_share_data, 0)[0]
    offset = 2
    end = 2 + total_len
    sizes_by_group = {}
    while offset < end:
        group_id, ke_len = struct.unpack_from(">HH", key_share_data, offset)
        offset += 4 + ke_len
        sizes_by_group[group_id] = ke_len

    assert sizes_by_group[tls_probe.X25519] == 32
    assert sizes_by_group[tls_probe.SECP256R1] == 65  # uncompressed EC point
    assert sizes_by_group[tls_probe.X25519MLKEM768] == 1184 + 32  # ML-KEM-768 ek || X25519 pub


# --- parse_server_hello ---

def _make_server_hello_body(cipher_suite, group_id, tls_version=0x0304):
    random_bytes = b"\x00" * 32
    session_id = b""

    ext_supported_versions = struct.pack(">HH", 0x002B, 2) + struct.pack(">H", tls_version)

    key_exchange = b"\x01" * 32
    key_share_data = struct.pack(">HH", group_id, len(key_exchange)) + key_exchange
    ext_key_share = struct.pack(">HH", 0x0033, len(key_share_data)) + key_share_data

    extensions = ext_supported_versions + ext_key_share

    return (
        struct.pack(">H", 0x0303)  # legacy_version
        + random_bytes
        + struct.pack(">B", len(session_id)) + session_id
        + struct.pack(">H", cipher_suite)
        + struct.pack(">B", 0x00)  # legacy_compression_method
        + struct.pack(">H", len(extensions)) + extensions
    )


def test_parse_server_hello_classical_group():
    body = _make_server_hello_body(0x1301, tls_probe.X25519)
    result = tls_probe.parse_server_hello(body, "example.com")

    assert result.error is None
    assert result.tls_version == "TLS1.3"
    assert result.cipher_suite_name == "TLS_AES_128_GCM_SHA256"
    assert result.group_name == "x25519"
    assert result.classification == "classical"


def test_parse_server_hello_hybrid_pqc_group():
    body = _make_server_hello_body(0x1302, tls_probe.X25519MLKEM768)
    result = tls_probe.parse_server_hello(body, "example.com")

    assert result.group_name == "X25519MLKEM768"
    assert result.classification == "hybrid-pqc"


def test_parse_server_hello_unrecognized_group():
    body = _make_server_hello_body(0x1301, 0x9999)
    result = tls_probe.parse_server_hello(body, "example.com")

    assert result.classification == "unknown"
    assert result.group_id == 0x9999
