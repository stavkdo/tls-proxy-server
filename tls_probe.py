"""A hand-built TLS 1.3 client, covering two use cases:

1. `probe()` -- lightweight: build a ClientHello offering both classical and
   hybrid-PQC groups, read only the plaintext ServerHello to see which group
   got selected, then disconnect. Used for quick group classification.
2. `connect()` -- a real client that completes the full handshake: derives
   the actual shared secret (ECDH, or ECDH+ML-KEM-768 decapsulation combined
   for the hybrid group), decrypts and validates the certificate chain, and
   protects the relayed application data with the negotiated keys. This is
   what makes a connection genuinely quantum-ready rather than just detecting
   PQC support from the sidelines.

Why this exists instead of using the stdlib `ssl` module: the OpenSSL build
Python is linked against here predates PQC group support (added in OpenSSL
3.2+), and even a newer OpenSSL wouldn't help because the stdlib `ssl` module
has no API to add custom groups to the ClientHello. So we build the
ClientHello ourselves, offering both classical and hybrid post-quantum
groups, using real key material from `cryptography` (classical) and
`kyber-py` (ML-KEM-768, pure Python, no native build step).

The real engine (`connect()`) is pinned to exactly one cipher suite,
`TLS_AES_256_GCM_SHA384` -- chosen for its larger quantum security margin
(see `tls_crypto.py`) -- and two groups, `x25519` (classical fallback) and
`X25519MLKEM768` (hybrid). A target that doesn't support that cipher or
either group fails the handshake cleanly (a TLS alert, surfaced as an
exception) rather than being silently misclassified.
"""

import hmac
import os
import socket
import struct
import time
from dataclasses import dataclass, field

import certifi
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes as hashes_mod
from cryptography.hazmat.primitives.asymmetric import ec, padding, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.verification import PolicyBuilder, Store
from kyber_py.ml_kem import ML_KEM_768

import tls_crypto

# --- TLS record / handshake wire constants ---
_RECORD_HANDSHAKE = 0x16
_RECORD_ALERT = 0x15
_RECORD_LEGACY_VERSION = 0x0301  # record-layer version field; kept at TLS 1.0 for compatibility

_HANDSHAKE_CLIENT_HELLO = 0x01
_HANDSHAKE_SERVER_HELLO = 0x02

_EXT_SERVER_NAME = 0x0000
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SIGNATURE_ALGORITHMS = 0x000D
_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_KEY_SHARE = 0x0033

_TLS1_0 = 0x0301
_TLS1_1 = 0x0302
_TLS1_2 = 0x0303
_TLS1_3 = 0x0304

_TLS_VERSION_NAMES = {_TLS1_0: "TLS1.0", _TLS1_1: "TLS1.1", _TLS1_2: "TLS1.2", _TLS1_3: "TLS1.3"}

CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

# Named groups (IANA TLS SupportedGroups registry)
SECP256R1 = 0x0017
X25519 = 0x001D
X25519MLKEM768 = 0x11EC  # draft-ietf-tls-ecdhe-mlkem, client share = ML-KEM-768 ek || X25519 pub

NAMED_GROUPS = {
    0x0017: ("secp256r1", "classical"),
    0x0018: ("secp384r1", "classical"),
    0x0019: ("secp521r1", "classical"),
    0x001D: ("x25519", "classical"),
    0x001E: ("x448", "classical"),
    0x11EC: ("X25519MLKEM768", "hybrid-pqc"),
    0x11EB: ("SecP256r1MLKEM768", "hybrid-pqc"),
    0x11ED: ("SecP384r1MLKEM1024", "hybrid-pqc"),
    0x6399: ("X25519Kyber768Draft00", "hybrid-pqc"),  # legacy Chrome draft codepoint, still seen live
}

DEFAULT_OFFERED_GROUPS = (X25519, SECP256R1, X25519MLKEM768)

_SIGNATURE_ALGORITHMS = (
    0x0403, 0x0503, 0x0603,  # ecdsa_secp256r1/384r1/521r1_sha256/384/512
    0x0804, 0x0805, 0x0806,  # rsa_pss_rsae_sha256/384/512
    0x0401, 0x0501, 0x0601,  # rsa_pkcs1_sha256/384/512
)

_SIG_SCHEME_INFO = {
    0x0403: ("ecdsa", hashes_mod.SHA256()),
    0x0503: ("ecdsa", hashes_mod.SHA384()),
    0x0603: ("ecdsa", hashes_mod.SHA512()),
    0x0804: ("rsa_pss", hashes_mod.SHA256()),
    0x0805: ("rsa_pss", hashes_mod.SHA384()),
    0x0806: ("rsa_pss", hashes_mod.SHA512()),
    0x0401: ("rsa_pkcs1", hashes_mod.SHA256()),
    0x0501: ("rsa_pkcs1", hashes_mod.SHA384()),
    0x0601: ("rsa_pkcs1", hashes_mod.SHA512()),
}

_SIG_SCHEME_NAMES = {
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
}

# Handshake message types (RFC 8446 S4) beyond ClientHello/ServerHello.
_HS_ENCRYPTED_EXTENSIONS = 0x08
_HS_CERTIFICATE = 0x0B
_HS_CERTIFICATE_VERIFY = 0x0F
_HS_FINISHED = 0x14

# Outer record ContentType values used post-ServerHello.
_RECORD_CHANGE_CIPHER_SPEC = 0x14
_RECORD_APPLICATION_DATA = 0x17

# The real engine's fixed cipher suite and offered groups (see module docstring).
REAL_CIPHER_SUITE = 0x1302  # TLS_AES_256_GCM_SHA384
REAL_GROUPS = (X25519, X25519MLKEM768)


class TlsError(Exception):
    """Base class for all errors raised by this module's TLS engine."""


class TlsAlertError(TlsError):
    def __init__(self, level, description):
        super().__init__(f"TLS alert (level={level}, description={description})")
        self.level = level
        self.description = description


class TlsProtocolError(TlsError):
    """The peer sent something that doesn't fit the TLS 1.3 state machine
    we implement (unexpected message/record type, malformed field, ...)."""


class TlsHandshakeError(TlsError):
    """A handshake we were otherwise able to parse failed for a substantive
    reason (bad signature, untrusted chain, unsupported version/cipher/group).
    Carries whatever TlsReport fields were already known at the point of
    failure, so callers don't lose partial information (e.g. the negotiated
    group) just because the handshake didn't finish."""

    def __init__(self, message, report=None):
        super().__init__(message)
        self.report = report


def classify_group(group_id):
    """Map a TLS named-group ID to (name, classification)."""
    return NAMED_GROUPS.get(group_id, (f"unknown(0x{group_id:04x})", "unknown"))


def _u8(n):
    return struct.pack(">B", n)


def _u16(n):
    return struct.pack(">H", n)


def _u24(n):
    return n.to_bytes(3, "big")


def _extension(ext_type, data):
    return _u16(ext_type) + _u16(len(data)) + data


def build_key_share_entry(group_id):
    """Return the raw key_exchange bytes to advertise for a given named group,
    generating real (if throwaway) key material -- servers implementing the
    hybrid group perform a real KEM encapsulation against it, so it must be
    validly formed, not a placeholder."""
    if group_id == X25519:
        priv = x25519.X25519PrivateKey.generate()
        return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if group_id == SECP256R1:
        priv = ec.generate_private_key(ec.SECP256R1())
        return priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    if group_id == X25519MLKEM768:
        ek, _dk = ML_KEM_768.keygen()
        x_priv = x25519.X25519PrivateKey.generate()
        x_pub = x_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        # ML-KEM-768 encapsulation key first, then the X25519 share.
        return ek + x_pub
    raise ValueError(f"no key_share builder for group 0x{group_id:04x}")


def build_client_hello(hostname, group_ids=DEFAULT_OFFERED_GROUPS):
    """Hand-construct a TLS 1.3 ClientHello record offering `group_ids`."""
    random_bytes = os.urandom(32)
    legacy_session_id = os.urandom(32)  # non-empty to request TLS1.3 middlebox-compat mode

    cipher_suite_bytes = b"".join(_u16(cs) for cs in CIPHER_SUITES)
    cipher_suites_field = _u16(len(cipher_suite_bytes)) + cipher_suite_bytes

    compression_methods_field = _u8(1) + _u8(0x00)

    hostname_bytes = hostname.encode("ascii")
    server_name_entry = _u8(0x00) + _u16(len(hostname_bytes)) + hostname_bytes
    server_name_list = _u16(len(server_name_entry)) + server_name_entry
    ext_server_name = _extension(_EXT_SERVER_NAME, server_name_list)

    supported_versions_data = _u8(2) + _u16(_TLS1_3)
    ext_supported_versions = _extension(_EXT_SUPPORTED_VERSIONS, supported_versions_data)

    groups_bytes = b"".join(_u16(g) for g in group_ids)
    supported_groups_data = _u16(len(groups_bytes)) + groups_bytes
    ext_supported_groups = _extension(_EXT_SUPPORTED_GROUPS, supported_groups_data)

    sig_algs_bytes = b"".join(_u16(sa) for sa in _SIGNATURE_ALGORITHMS)
    sig_algs_data = _u16(len(sig_algs_bytes)) + sig_algs_bytes
    ext_sig_algs = _extension(_EXT_SIGNATURE_ALGORITHMS, sig_algs_data)

    key_share_entries = bytearray()
    for group_id in group_ids:
        key_exchange = build_key_share_entry(group_id)
        key_share_entries += _u16(group_id) + _u16(len(key_exchange)) + key_exchange
    key_share_data = _u16(len(key_share_entries)) + bytes(key_share_entries)
    ext_key_share = _extension(_EXT_KEY_SHARE, key_share_data)

    extensions_blob = (
        ext_server_name + ext_supported_versions + ext_supported_groups + ext_sig_algs + ext_key_share
    )
    extensions_field = _u16(len(extensions_blob)) + extensions_blob

    body = (
        _u16(_TLS1_2)  # legacy_version
        + random_bytes
        + _u8(len(legacy_session_id)) + legacy_session_id
        + cipher_suites_field
        + compression_methods_field
        + extensions_field
    )

    handshake_msg = _u8(_HANDSHAKE_CLIENT_HELLO) + _u24(len(body)) + body
    record = _u8(_RECORD_HANDSHAKE) + _u16(_RECORD_LEGACY_VERSION) + _u16(len(handshake_msg)) + handshake_msg
    return record


@dataclass
class ProbeResult:
    host: str
    tls_version: str | None = None
    cipher_suite: int | None = None
    cipher_suite_name: str | None = None
    group_id: int | None = None
    group_name: str | None = None
    classification: str = "unknown"
    error: str | None = None


def _parse_server_hello_fields(handshake_body: bytes):
    """Parse the body of a ServerHello handshake message (i.e. the bytes
    after the 4-byte handshake header). Returns
    (cipher_suite, selected_version, group_id, key_exchange_bytes) --
    key_exchange_bytes is the server's raw key_share value (needed to
    actually compute a shared secret), or None if absent."""
    offset = 0
    legacy_version = struct.unpack_from(">H", handshake_body, offset)[0]
    offset += 2
    offset += 32  # random
    session_id_len = handshake_body[offset]
    offset += 1 + session_id_len
    cipher_suite = struct.unpack_from(">H", handshake_body, offset)[0]
    offset += 2
    offset += 1  # legacy_compression_method

    selected_version = legacy_version
    group_id = None
    key_exchange = None

    if offset < len(handshake_body):
        ext_total_len = struct.unpack_from(">H", handshake_body, offset)[0]
        offset += 2
        ext_end = offset + ext_total_len
        while offset < ext_end:
            ext_type, ext_len = struct.unpack_from(">HH", handshake_body, offset)
            offset += 4
            ext_data = handshake_body[offset: offset + ext_len]
            offset += ext_len
            if ext_type == _EXT_SUPPORTED_VERSIONS and len(ext_data) >= 2:
                selected_version = struct.unpack_from(">H", ext_data, 0)[0]
            elif ext_type == _EXT_KEY_SHARE and len(ext_data) >= 2:
                group_id = struct.unpack_from(">H", ext_data, 0)[0]
                ke_len = struct.unpack_from(">H", ext_data, 2)[0]
                key_exchange = ext_data[4:4 + ke_len]

    return cipher_suite, selected_version, group_id, key_exchange


def parse_server_hello(handshake_body: bytes, host: str) -> ProbeResult:
    """Parse a ServerHello and classify the negotiated group. (Lightweight
    path -- doesn't need the raw key_exchange bytes, just the group id.)"""
    cipher_suite, selected_version, group_id, _key_exchange = _parse_server_hello_fields(handshake_body)

    group_name, classification = (None, "unknown")
    if group_id is not None:
        group_name, classification = classify_group(group_id)
    elif selected_version < _TLS1_3:
        classification = "pre-tls1.3"

    return ProbeResult(
        host=host,
        tls_version=_TLS_VERSION_NAMES.get(selected_version, f"0x{selected_version:04x}"),
        cipher_suite=cipher_suite,
        cipher_suite_name=CIPHER_SUITES.get(cipher_suite, f"0x{cipher_suite:04x}"),
        group_id=group_id,
        group_name=group_name,
        classification=classification,
    )


def _recv_exact(sock, n, deadline):
    buf = bytearray()
    while len(buf) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out waiting for server response")
        sock.settimeout(remaining)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed before a full response was received")
        buf += chunk
    return bytes(buf)


def _read_record(sock, deadline):
    header = _recv_exact(sock, 5, deadline)
    record_type = header[0]
    length = struct.unpack(">H", header[3:5])[0]
    payload = _recv_exact(sock, length, deadline)
    return record_type, payload


def _read_server_hello(sock, deadline) -> bytes:
    """Read raw (pre-encryption) records until a complete ServerHello
    handshake message has arrived. Returns the full message, i.e.
    type(1) + length(3) + body."""
    handshake_buf = bytearray()
    needed = None
    while True:
        record_type, payload = _read_record(sock, deadline)
        if record_type == _RECORD_ALERT:
            raise TlsAlertError(payload[0], payload[1])
        if record_type != _RECORD_HANDSHAKE:
            raise TlsProtocolError(f"unexpected record type 0x{record_type:02x}")

        handshake_buf += payload
        if needed is None and len(handshake_buf) >= 4:
            msg_type = handshake_buf[0]
            if msg_type != _HANDSHAKE_SERVER_HELLO:
                raise TlsProtocolError(f"unexpected handshake message type 0x{msg_type:02x}")
            needed = 4 + int.from_bytes(handshake_buf[1:4], "big")
        if needed is not None and len(handshake_buf) >= needed:
            return bytes(handshake_buf[:needed])


def probe(hostname, port=443, timeout=5.0) -> ProbeResult:
    """Connect to hostname:port, send a crafted ClientHello offering both
    classical and hybrid-PQC groups, and classify whichever group the server
    selects from the (plaintext) ServerHello. Never completes the handshake."""
    deadline = time.monotonic() + timeout

    try:
        client_hello = build_client_hello(hostname)
    except Exception as exc:
        return ProbeResult(host=hostname, error=f"failed to build ClientHello: {exc}")

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            sock.sendall(client_hello)
            server_hello_msg = _read_server_hello(sock, deadline)
            return parse_server_hello(server_hello_msg[4:], hostname)
    except TlsError as exc:
        return ProbeResult(host=hostname, error=str(exc))
    except (TimeoutError, ConnectionError, OSError, socket.gaierror) as exc:
        return ProbeResult(host=hostname, error=str(exc))


# ===========================================================================
# Real client-role engine: completes the full handshake, protects relayed
# application data with the negotiated keys.
# ===========================================================================


@dataclass
class _KeyShare:
    group_id: int
    public_bytes: bytes
    private: object  # X25519PrivateKey, or (X25519PrivateKey, ml_kem_dk) for the hybrid group


def _generate_key_share(group_id) -> _KeyShare:
    if group_id == X25519:
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return _KeyShare(group_id, pub, priv)
    if group_id == X25519MLKEM768:
        ek, dk = ML_KEM_768.keygen()
        x_priv = x25519.X25519PrivateKey.generate()
        x_pub = x_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return _KeyShare(group_id, ek + x_pub, (x_priv, dk))
    raise ValueError(f"no key_share builder for group 0x{group_id:04x}")


def _build_real_client_hello(hostname, group_ids):
    """Like build_client_hello, but offering only REAL_CIPHER_SUITE and
    returning the handshake-message bytes (for the transcript hash) and the
    private key material needed to actually complete the handshake."""
    random_bytes = os.urandom(32)
    legacy_session_id = os.urandom(32)

    cipher_suites_field = _u16(2) + _u16(REAL_CIPHER_SUITE)
    compression_methods_field = _u8(1) + _u8(0x00)

    hostname_bytes = hostname.encode("ascii")
    server_name_entry = _u8(0x00) + _u16(len(hostname_bytes)) + hostname_bytes
    server_name_list = _u16(len(server_name_entry)) + server_name_entry
    ext_server_name = _extension(_EXT_SERVER_NAME, server_name_list)

    supported_versions_data = _u8(2) + _u16(_TLS1_3)
    ext_supported_versions = _extension(_EXT_SUPPORTED_VERSIONS, supported_versions_data)

    groups_bytes = b"".join(_u16(g) for g in group_ids)
    supported_groups_data = _u16(len(groups_bytes)) + groups_bytes
    ext_supported_groups = _extension(_EXT_SUPPORTED_GROUPS, supported_groups_data)

    sig_algs_bytes = b"".join(_u16(sa) for sa in _SIGNATURE_ALGORITHMS)
    sig_algs_data = _u16(len(sig_algs_bytes)) + sig_algs_bytes
    ext_sig_algs = _extension(_EXT_SIGNATURE_ALGORITHMS, sig_algs_data)

    key_shares = {}
    key_share_entries = bytearray()
    for group_id in group_ids:
        ks = _generate_key_share(group_id)
        key_shares[group_id] = ks
        key_share_entries += _u16(group_id) + _u16(len(ks.public_bytes)) + ks.public_bytes
    key_share_data = _u16(len(key_share_entries)) + bytes(key_share_entries)
    ext_key_share = _extension(_EXT_KEY_SHARE, key_share_data)

    extensions_blob = (
        ext_server_name + ext_supported_versions + ext_supported_groups + ext_sig_algs + ext_key_share
    )
    extensions_field = _u16(len(extensions_blob)) + extensions_blob

    body = (
        _u16(_TLS1_2)
        + random_bytes
        + _u8(len(legacy_session_id)) + legacy_session_id
        + cipher_suites_field
        + compression_methods_field
        + extensions_field
    )
    handshake_msg = _u8(_HANDSHAKE_CLIENT_HELLO) + _u24(len(body)) + body
    record = _u8(_RECORD_HANDSHAKE) + _u16(_RECORD_LEGACY_VERSION) + _u16(len(handshake_msg)) + handshake_msg
    return handshake_msg, record, key_shares


def _compute_shared_secret(group_id, private_material, peer_key_exchange: bytes) -> bytes:
    if group_id == X25519:
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_key_exchange)
        return private_material.exchange(peer_pub)
    if group_id == X25519MLKEM768:
        x_priv, mlkem_dk = private_material
        ml_kem_ciphertext_len = 1088
        ciphertext = peer_key_exchange[:ml_kem_ciphertext_len]
        peer_x_pub_bytes = peer_key_exchange[ml_kem_ciphertext_len:ml_kem_ciphertext_len + 32]
        pq_shared = ML_KEM_768.decaps(mlkem_dk, ciphertext)
        peer_x_pub = x25519.X25519PublicKey.from_public_bytes(peer_x_pub_bytes)
        classical_shared = x_priv.exchange(peer_x_pub)
        return pq_shared + classical_shared  # PQ-first, mirroring the key_share byte order
    raise ValueError(f"no shared-secret computation for group 0x{group_id:04x}")


def _pop_handshake_message(buf: bytearray):
    """Pop one complete handshake message (type+len+body) off the front of
    buf if one is fully present, else return None (need more data)."""
    if len(buf) < 4:
        return None
    length = int.from_bytes(buf[1:4], "big")
    total = 4 + length
    if len(buf) < total:
        return None
    msg = bytes(buf[:total])
    del buf[:total]
    return msg


def _read_raw_record(sock, deadline) -> bytes:
    """Read one complete TLS record, header and payload together (needed
    so RecordProtector.open can reconstruct the AEAD associated data)."""
    header = _recv_exact(sock, 5, deadline)
    length = struct.unpack(">H", header[3:5])[0]
    payload = _recv_exact(sock, length, deadline)
    return header + payload


def _next_decrypted_handshake_message(sock, deadline, protector, buf: bytearray) -> bytes:
    """Return the next complete decrypted handshake message, decrypting
    raw records as needed. Transparently skips the plaintext
    ChangeCipherSpec compatibility record servers send when we offer a
    non-empty legacy_session_id."""
    while True:
        msg = _pop_handshake_message(buf)
        if msg is not None:
            return msg
        raw = _read_raw_record(sock, deadline)
        if raw[0] == _RECORD_CHANGE_CIPHER_SPEC:
            continue
        if raw[0] != _RECORD_APPLICATION_DATA:
            raise TlsProtocolError(f"unexpected outer record type 0x{raw[0]:02x}")
        content, content_type = protector.open(raw)
        if content_type == _RECORD_ALERT:
            raise TlsAlertError(content[0], content[1])
        if content_type != _RECORD_HANDSHAKE:
            raise TlsProtocolError(f"unexpected inner content type 0x{content_type:02x}")
        buf += content


def _parse_certificate_message(body: bytes):
    """RFC 8446 S4.4.2 Certificate. Returns a list of x509 certs, leaf first."""
    offset = 0
    ctx_len = body[offset]
    offset += 1 + ctx_len  # certificate_request_context -- empty for server certs
    cert_list_len = int.from_bytes(body[offset:offset + 3], "big")
    offset += 3
    end = offset + cert_list_len

    certs = []
    while offset < end:
        cert_len = int.from_bytes(body[offset:offset + 3], "big")
        offset += 3
        cert_der = body[offset:offset + cert_len]
        offset += cert_len
        ext_len = struct.unpack_from(">H", body, offset)[0]
        offset += 2 + ext_len
        certs.append(x509.load_der_x509_certificate(cert_der))
    return certs


def _verify_certificate_verify(leaf_cert, sig_scheme: int, signature: bytes, signed_content: bytes):
    """Raises cryptography.exceptions.InvalidSignature on failure."""
    info = _SIG_SCHEME_INFO.get(sig_scheme)
    if info is None:
        raise TlsProtocolError(f"unsupported CertificateVerify signature scheme 0x{sig_scheme:04x}")
    kind, hash_algo = info
    public_key = leaf_cert.public_key()
    if kind == "ecdsa":
        public_key.verify(signature, signed_content, ec.ECDSA(hash_algo))
    elif kind == "rsa_pss":
        public_key.verify(
            signature, signed_content,
            padding.PSS(mgf=padding.MGF1(hash_algo), salt_length=hash_algo.digest_size),
            hash_algo,
        )
    elif kind == "rsa_pkcs1":
        public_key.verify(signature, signed_content, padding.PKCS1v15(), hash_algo)


def _hostname_matches_cert(cert, hostname: str) -> bool:
    """Simple exact-match SAN check -- no wildcard support. This is a cheap,
    independent signal for the report; `_validate_chain` below does the real
    (wildcard-aware) hostname check as part of full path validation."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    return hostname in san.get_values_for_type(x509.DNSName)


_default_trusted_roots = None


def _load_default_trusted_roots():
    global _default_trusted_roots
    if _default_trusted_roots is None:
        with open(certifi.where(), "rb") as f:
            _default_trusted_roots = x509.load_pem_x509_certificates(f.read())
    return _default_trusted_roots


def _validate_chain(leaf_cert, intermediate_certs, hostname: str, trusted_roots=None) -> None:
    """Raises on failure (untrusted chain, expired, hostname mismatch, ...)."""
    roots = trusted_roots if trusted_roots is not None else _load_default_trusted_roots()
    store = Store(roots)
    verifier = PolicyBuilder().store(store).build_server_verifier(x509.DNSName(hostname))
    verifier.verify(leaf_cert, intermediate_certs)


@dataclass
class TlsReport:
    host: str
    tls_version: str | None = None
    cipher_suite_name: str | None = None
    group_name: str | None = None
    classification: str = "unknown"
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_valid_after: str | None = None
    cert_signature_algorithm: str | None = None
    chain_valid: bool = False
    hostname_matches: bool = False
    error: str | None = None


class ClientTlsConnection:
    """A completed TLS 1.3 connection, protecting application data with the
    negotiated (possibly post-quantum) keys. `.report` carries everything
    learned during the handshake."""

    def __init__(self, sock, app_write: "tls_crypto.RecordProtector", app_read: "tls_crypto.RecordProtector", report: TlsReport):
        self._sock = sock
        self._write = app_write
        self._read = app_read
        self.report = report

    def send(self, data: bytes) -> None:
        self._sock.sendall(self._write.seal(data, content_type=_RECORD_APPLICATION_DATA))

    def recv(self, timeout: float = 10.0) -> bytes:
        """Returns the next chunk of application data, or b"" if the peer
        closed the connection (either a clean close_notify alert, or an
        abrupt TCP close) -- callers should treat an empty return the same
        way as a plain socket's recv() returning b"". Transparently discards
        post-handshake handshake-type messages (e.g. NewSessionTicket)
        rather than returning or erroring on them."""
        deadline = time.monotonic() + timeout
        while True:
            try:
                raw = _read_raw_record(self._sock, deadline)
            except ConnectionError:
                return b""
            if raw[0] == _RECORD_CHANGE_CIPHER_SPEC:
                continue
            content, content_type = self._read.open(raw)
            if content_type == _RECORD_APPLICATION_DATA:
                return content
            if content_type == _RECORD_ALERT:
                level, description = content[0], content[1]
                if level == 1 and description == 0:  # close_notify
                    return b""
                raise TlsAlertError(level, description)
            if content_type == _RECORD_HANDSHAKE:
                continue
            raise TlsProtocolError(f"unexpected content type 0x{content_type:02x}")

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def connect(hostname, port=443, timeout=10.0, trusted_roots=None, connect_host=None) -> ClientTlsConnection:
    """Complete a real TLS 1.3 handshake against hostname:port, offering
    REAL_GROUPS and REAL_CIPHER_SUITE. Validates the certificate chain and
    hostname, verifies the server's CertificateVerify and Finished, sends
    our own Finished, and returns a connection ready to relay application
    data under the negotiated (possibly hybrid-PQC) keys.

    `connect_host`, when given, is dialed at the TCP level instead of
    `hostname` -- `hostname` still drives SNI and certificate/hostname
    validation. Mainly for tests that need to point at 127.0.0.1 while
    validating against a chosen test hostname (c.f. curl's --resolve).

    Raises TlsHandshakeError (with a partially-filled `.report` when
    possible), TlsProtocolError, TlsAlertError, or a plain OSError/
    TimeoutError/socket.gaierror on failure.
    """
    deadline = time.monotonic() + timeout
    report = TlsReport(host=hostname)

    handshake_msg, record, key_shares = _build_real_client_hello(hostname, REAL_GROUPS)

    sock = socket.create_connection((connect_host or hostname, port), timeout=timeout)
    try:
        transcript = tls_crypto.TranscriptHash(tls_crypto.SHA384)
        transcript.update(handshake_msg)
        sock.sendall(record)

        server_hello_msg = _read_server_hello(sock, deadline)
        transcript.update(server_hello_msg)

        cipher_suite, selected_version, group_id, peer_key_exchange = _parse_server_hello_fields(
            server_hello_msg[4:]
        )
        group_name, classification = classify_group(group_id) if group_id is not None else (None, "unknown")
        report.tls_version = _TLS_VERSION_NAMES.get(selected_version, f"0x{selected_version:04x}")
        report.cipher_suite_name = CIPHER_SUITES.get(cipher_suite, f"0x{cipher_suite:04x}")
        report.group_name = group_name
        report.classification = classification

        if selected_version != _TLS1_3:
            raise TlsHandshakeError(f"server selected {report.tls_version}, only TLS 1.3 is supported", report)
        if cipher_suite != REAL_CIPHER_SUITE:
            raise TlsHandshakeError(f"server selected unsupported cipher 0x{cipher_suite:04x}", report)
        if group_id not in key_shares or peer_key_exchange is None:
            raise TlsHandshakeError(f"server selected unsupported group {group_id!r}", report)

        ks = key_shares[group_id]
        shared_secret = _compute_shared_secret(group_id, ks.private, peer_key_exchange)

        schedule = tls_crypto.KeySchedule(tls_crypto.SHA384)
        client_hs_secret, server_hs_secret = schedule.handshake_traffic_secrets(
            shared_secret, transcript.digest()
        )
        hs_write = tls_crypto.RecordProtector(client_hs_secret)
        hs_read = tls_crypto.RecordProtector(server_hs_secret)

        buf = bytearray()
        leaf_cert = None
        intermediate_certs = []
        got_finished = False

        while not got_finished:
            msg = _next_decrypted_handshake_message(sock, deadline, hs_read, buf)
            msg_type = msg[0]
            body = msg[4:]

            if msg_type == _HS_CERTIFICATE:
                certs = _parse_certificate_message(body)
                if not certs:
                    raise TlsHandshakeError("server sent an empty Certificate message", report)
                leaf_cert, *intermediate_certs = certs
                transcript.update(msg)

            elif msg_type == _HS_CERTIFICATE_VERIFY:
                if leaf_cert is None:
                    raise TlsProtocolError("CertificateVerify received before Certificate")
                th_before = transcript.digest()
                sig_scheme = struct.unpack_from(">H", body, 0)[0]
                sig_len = struct.unpack_from(">H", body, 2)[0]
                signature = body[4:4 + sig_len]
                transcript.update(msg)

                signed_content = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00" + th_before
                try:
                    _verify_certificate_verify(leaf_cert, sig_scheme, signature, signed_content)
                except InvalidSignature:
                    raise TlsHandshakeError("CertificateVerify signature check failed", report)
                report.cert_signature_algorithm = _SIG_SCHEME_NAMES.get(sig_scheme, f"0x{sig_scheme:04x}")

            elif msg_type == _HS_FINISHED:
                th_before = transcript.digest()
                expected = tls_crypto.finished_verify_data(server_hs_secret, th_before)
                if not hmac.compare_digest(expected, body):
                    raise TlsHandshakeError("server Finished verification failed", report)
                transcript.update(msg)
                got_finished = True

            else:
                # EncryptedExtensions, CertificateRequest, etc. -- not parsed,
                # just included in the transcript.
                transcript.update(msg)

        if leaf_cert is None:
            raise TlsHandshakeError("handshake completed without a server Certificate message", report)

        report.cert_subject = leaf_cert.subject.rfc4514_string()
        report.cert_issuer = leaf_cert.issuer.rfc4514_string()
        report.cert_not_valid_after = leaf_cert.not_valid_after_utc.isoformat()
        report.hostname_matches = _hostname_matches_cert(leaf_cert, hostname)
        try:
            _validate_chain(leaf_cert, intermediate_certs, hostname, trusted_roots)
            report.chain_valid = True
        except Exception as exc:
            report.chain_valid = False
            report.error = f"certificate chain validation failed: {exc}"

        th_through_server_finished = transcript.digest()
        client_ap_secret, server_ap_secret = schedule.application_traffic_secrets(th_through_server_finished)

        client_finished_verify_data = tls_crypto.finished_verify_data(
            client_hs_secret, th_through_server_finished
        )
        client_finished_msg = (
            _u8(_HS_FINISHED) + _u24(len(client_finished_verify_data)) + client_finished_verify_data
        )
        sock.sendall(hs_write.seal(client_finished_msg, content_type=_RECORD_HANDSHAKE))

        app_write = tls_crypto.RecordProtector(client_ap_secret)
        app_read = tls_crypto.RecordProtector(server_ap_secret)
        return ClientTlsConnection(sock, app_write, app_read, report)

    except TlsHandshakeError:
        sock.close()
        raise
    except (TlsError, TimeoutError, ConnectionError, OSError, socket.gaierror):
        sock.close()
        raise


def probe_full(hostname, port=443, timeout=10.0, trusted_roots=None) -> TlsReport:
    """Convenience wrapper for the standalone 'scan this domain' use case:
    complete a real handshake, grab the report, and disconnect -- no
    relaying. Never raises; failures are reported via `.error`."""
    try:
        conn = connect(hostname, port=port, timeout=timeout, trusted_roots=trusted_roots)
    except TlsHandshakeError as exc:
        report = exc.report or TlsReport(host=hostname)
        if not report.error:
            report.error = str(exc)
        return report
    except (TlsError, TimeoutError, ConnectionError, OSError, socket.gaierror) as exc:
        return TlsReport(host=hostname, error=str(exc))
    else:
        conn.close()
        return conn.report
