"""End-to-end test of the real client-role TLS 1.3 engine (tls_probe.connect)
against a local test server.

The local server uses stdlib `ssl` (classical-only, since stdlib can't do
PQC groups) -- so this validates the classical path end to end: real key
exchange, certificate decryption/validation, Finished verification in both
directions, and application-data relay under the negotiated keys. A live
test against a real hybrid-PQC-capable public host is a manual verification
step, not part of this automated suite (network-dependent).
"""

import socket
import ssl
import threading

import pytest

import ca
import tls_probe


TEST_HOSTNAME = "engine-test.local"


def _start_echo_server(cert_path, key_path, reply: bytes):
    """Starts a background thread serving one TLS connection: reads one
    message, sends `reply`, closes. Returns (port, thread, errors_list)."""
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.num_tickets = 0
    server_context.load_cert_chain(cert_path, key_path)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    _, port = listener.getsockname()

    errors = []

    def _serve():
        try:
            raw_conn, _ = listener.accept()
            with server_context.wrap_socket(raw_conn, server_side=True) as tls_conn:
                tls_conn.recv(4096)
                tls_conn.sendall(reply)
        except Exception as exc:
            errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return port, thread, errors


@pytest.fixture
def ca_and_cert(tmp_path):
    ca_key, ca_cert, _, _ = ca.ensure_root_ca(ca_dir=tmp_path / "ca")
    key_path, cert_path = ca.get_leaf_cert(TEST_HOSTNAME, ca_key, ca_cert, cache_dir=tmp_path / "leaves")
    return ca_cert, key_path, cert_path


def test_connect_completes_classical_handshake_and_relays_data(ca_and_cert):
    ca_cert, key_path, cert_path = ca_and_cert
    port, thread, errors = _start_echo_server(cert_path, key_path, reply=b"pong")

    conn = tls_probe.connect(
        TEST_HOSTNAME, port=port, timeout=5.0, trusted_roots=[ca_cert], connect_host="127.0.0.1"
    )
    try:
        report = conn.report
        assert report.error is None
        assert report.tls_version == "TLS1.3"
        assert report.cipher_suite_name == "TLS_AES_256_GCM_SHA384"
        # stdlib OpenSSL doesn't understand our hybrid group id, so it falls
        # back to the one classical group we also offered.
        assert report.classification == "classical"
        assert report.group_name == "x25519"
        assert report.chain_valid is True
        assert report.hostname_matches is True
        assert TEST_HOSTNAME in report.cert_subject

        conn.send(b"ping")
        assert conn.recv() == b"pong"
    finally:
        conn.close()

    thread.join(timeout=5)
    assert not errors, f"server-side error: {errors}"


def test_connect_flags_hostname_mismatch(ca_and_cert):
    ca_cert, key_path, cert_path = ca_and_cert
    port, thread, errors = _start_echo_server(cert_path, key_path, reply=b"pong")

    # The server's cert covers TEST_HOSTNAME, but we validate against a
    # different name -- the crypto/handshake still succeeds (the server
    # doesn't care what name we asked for), but our own chain/hostname
    # validation should correctly flag the mismatch. We never exercise
    # send()/recv() here, so the server is left blocked in recv() until we
    # close -- that abrupt close is a benign shutdown race on the server
    # side (same class of thing as test_proxy_sni.py's teardown), not
    # something this test is checking, so `errors` is intentionally not
    # asserted on.
    conn = tls_probe.connect(
        "wrong-host.local", port=port, timeout=5.0, trusted_roots=[ca_cert], connect_host="127.0.0.1"
    )
    try:
        assert conn.report.hostname_matches is False
        assert conn.report.chain_valid is False
        assert conn.report.error is not None
    finally:
        conn.close()
    thread.join(timeout=5)


def test_probe_full_returns_error_report_on_connection_refused():
    report = tls_probe.probe_full("127.0.0.1", port=1, timeout=1.0)
    assert report.error is not None
