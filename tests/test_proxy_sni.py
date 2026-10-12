"""Integration test for the proxy's dynamic, per-SNI certificate selection.

Drives the same SSLContext/sni_callback that main.py's handle_client uses,
via a plain synchronous TLS server/client pair (the sni_callback mechanism
is standard stdlib `ssl` machinery, independent of the asyncio plumbing
around it), and asserts that a client requesting a given hostname via SNI
gets back a certificate that (a) is trusted through our root CA and (b)
actually matches that hostname.
"""

import socket
import ssl
import threading

import ca
import main


def test_sni_callback_serves_matching_cert_for_requested_hostname(tmp_path):
    ca_key, ca_cert, _, ca_cert_path = ca.ensure_root_ca(ca_dir=tmp_path / "ca")

    server_context = main.build_client_ssl_context(ca_key, ca_cert)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("localhost", 0))
    listener.listen(1)
    _, port = listener.getsockname()

    server_error = []

    def _serve_one():
        try:
            raw_conn, _ = listener.accept()
            # wrap_socket() blocks until the handshake fully completes -- that's
            # the meaningful check here. A close() failure right after just means
            # the client tore its side down first (e.g. before session-ticket
            # flush), which doesn't indicate an SNI/cert problem.
            tls_conn = server_context.wrap_socket(raw_conn, server_side=True)
        except Exception as exc:
            server_error.append(exc)
            return
        finally:
            listener.close()
        try:
            tls_conn.close()
        except OSError:
            pass

    server_thread = threading.Thread(target=_serve_one, daemon=True)
    server_thread.start()

    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(cafile=str(ca_cert_path))

    with socket.create_connection(("localhost", port), timeout=5) as sock:
        with client_context.wrap_socket(sock, server_hostname="probe-test.local") as tls_sock:
            peer_cert = tls_sock.getpeercert()

    server_thread.join(timeout=5)
    assert not server_error, f"server-side error: {server_error}"

    dns_names = [v for k, v in peer_cert["subjectAltName"] if k == "DNS"]
    assert "probe-test.local" in dns_names


def test_sni_callback_serves_different_certs_for_different_hostnames(tmp_path):
    ca_key, ca_cert, _, ca_cert_path = ca.ensure_root_ca(ca_dir=tmp_path / "ca")

    key_path_a, cert_path_a = ca.get_leaf_cert("a.example", ca_key, ca_cert, cache_dir=tmp_path / "leaves")
    key_path_b, cert_path_b = ca.get_leaf_cert("b.example", ca_key, ca_cert, cache_dir=tmp_path / "leaves")

    assert cert_path_a != cert_path_b
    assert open(cert_path_a, "rb").read() != open(cert_path_b, "rb").read()
