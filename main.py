import asyncio
import socket
import ssl
import ca
import tls_probe



async def relay_client_to_target(client_socket, sslobj_client, incoming_client, target_conn, loop):
    """Browser -> proxy (stdlib ssl, decrypted here) -> target (our engine,
    re-encrypted with the negotiated, possibly post-quantum keys)."""
    try:
        while True:
            raw_encrypted = await loop.sock_recv(client_socket, 8192)
            if not raw_encrypted:
                break
            incoming_client.write(raw_encrypted)
            while True:
                try:
                    plaintext = sslobj_client.read(8192)
                    if not plaintext:
                        break
                    print(f"[Client->Target] Decrypted Content: {plaintext[:50]}")
                    await loop.run_in_executor(None, target_conn.send, plaintext)
                except ssl.SSLWantReadError:
                    break
    except Exception as e:
        print(f"Error in Client->Target: {e}")


async def relay_target_to_client(client_socket, sslobj_client, outgoing_client, target_conn, loop):
    """Target (our engine, decrypted here) -> proxy -> browser (stdlib ssl,
    re-encrypted with the browser-facing cert/session)."""
    try:
        while True:
            plaintext = await loop.run_in_executor(None, lambda: target_conn.recv(timeout=300.0))
            if not plaintext:
                break
            print(f"[Target->Client] Decrypted Content: {plaintext[:50]}")
            sslobj_client.write(plaintext)
            to_send = outgoing_client.read()
            if to_send:
                await loop.sock_sendall(client_socket, to_send)
    except Exception as e:
        print(f"Error in Target->Client: {e}")



async def do_ssl_handshake(sock, sslobj, incoming, outgoing):
    loop = asyncio.get_running_loop()
    while True:
        try:
            sslobj.do_handshake()
            print("[+] SSL Handshake completed in memory!")
            to_send = outgoing.read()
            if to_send:
                await loop.sock_sendall(sock, to_send)
            break
        except ssl.SSLWantReadError:
            # reading from the socket and feeding data to the SSLObject   
            to_send = outgoing.read()
            if to_send:
                await loop.sock_sendall(sock, to_send)
            # waiting for data from the client to continue the handshake
            received = await loop.sock_recv(sock, 8192)
            if not received:
                raise Exception("Connection closed during handshake")
            # writing received data to the incoming BIO for the SSLObject to decrypt and process the handshake    
            incoming.write(received)



def build_client_ssl_context(ca_key, ca_cert, default_hostname=None):
    """Build a server-side SSLContext that mints (and caches) a fresh
    certificate for whatever hostname the connecting client's SNI names,
    signed by our local root CA -- this is what lets the proxy transparently
    impersonate arbitrary domains instead of one fixed host.

    `default_hostname`, when given, is used to pre-load a certificate before
    the handshake starts, in case the client doesn't send SNI at all.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # a fresh SSLContext is built per connection, so resumption tickets would
    # never be used anyway -- skip issuing them.
    context.num_tickets = 0

    def _sni_callback(sslobj, server_name, ssl_ctx):
        hostname = server_name or default_hostname
        if not hostname:
            return
        key_path, cert_path = ca.get_leaf_cert(hostname, ca_key, ca_cert)
        per_host_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        per_host_context.num_tickets = 0
        per_host_context.load_cert_chain(cert_path, key_path)
        sslobj.context = per_host_context

    context.sni_callback = _sni_callback

    if default_hostname:
        key_path, cert_path = ca.get_leaf_cert(default_hostname, ca_key, ca_cert)
        context.load_cert_chain(cert_path, key_path)

    return context


async def handle_client(client_socket, ca_key, ca_cert):
    loop = asyncio.get_running_loop()
    target_conn = None
    try:
        print("[DEBUG] handle_client started")
        client_socket.setblocking(False)

       # wait for the initial CONNECT request from the client to determine target host and port
        data = await loop.sock_recv(client_socket, 4096)
        request = data.decode('utf-8', errors='ignore')
        if "CONNECT" not in request: return

        # extracting target host and port from the CONNECT request
        target_host = request.split(' ')[1].split(':')[0]
        target_port = int(request.split(' ')[1].split(':')[1])
        print(f"[*] Connecting to {target_host}:{target_port}")

        # real, handshake-completing connection to the target -- this *is* the
        # PQC-readiness check now (whichever group actually got negotiated),
        # not a side-channel probe, and it also gives us real certificate data.
        try:
            target_conn = await loop.run_in_executor(None, tls_probe.connect, target_host, target_port)
        except tls_probe.TlsHandshakeError as exc:
            report = exc.report
            if report and report.error is None:
                report.error = str(exc)
            print(f"[PQC] {target_host}: handshake failed ({exc})" + (f" [{report.classification}]" if report else ""))
            return
        except tls_probe.TlsError as exc:
            print(f"[PQC] {target_host}: handshake failed ({exc})")
            return

        report = target_conn.report
        print(
            f"[PQC] {target_host}: {report.classification} "
            f"(group={report.group_name}, cipher={report.cipher_suite_name}, version={report.tls_version}, "
            f"chain_valid={report.chain_valid}, hostname_matches={report.hostname_matches})"
        )
        if report.error:
            print(f"[PQC] {target_host}: note: {report.error}")

        await loop.sock_sendall(client_socket, b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # starting SSL handshake with the client (browser-facing leg --
        # still stdlib ssl/classical for now, see FLOW.md's scope boundary)
        client_context = build_client_ssl_context(ca_key, ca_cert, default_hostname=target_host)

        incoming_client = ssl.MemoryBIO()
        outgoing_client = ssl.MemoryBIO()
        sslobj_client = client_context.wrap_bio(incoming_client, outgoing_client, server_side=True)
        await do_ssl_handshake(client_socket, sslobj_client, incoming_client, outgoing_client)

        print("[*] Both Handshakes complete!")

        # start processing data in both directions
        await asyncio.gather(
            relay_client_to_target(client_socket, sslobj_client, incoming_client, target_conn, loop),
            relay_target_to_client(client_socket, sslobj_client, outgoing_client, target_conn, loop),
        )

    except Exception as e:
        print(f"[!] Handle Client Error: {e}")
    finally:
        client_socket.close()
        if target_conn:
            target_conn.close()



async def start_proxy():
    loop = asyncio.get_running_loop()

    listen_port = 4443

    # local root CA, used to mint a fresh per-domain leaf certificate for every
    # intercepted connection (see build_client_ssl_context)
    ca_key, ca_cert, _, _ = ca.ensure_root_ca()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", listen_port))
    server.listen(100)
    server.setblocking(False)
    print(f"[*] Proxy listening on port {listen_port}")

    while True:
        client_socket, client_address = await loop.sock_accept(server)
        print(f"[*] Accepted connection from {client_address}")
        client_handler = asyncio.create_task(handle_client(client_socket, ca_key, ca_cert))
        


if __name__ == "__main__":
    asyncio.run(start_proxy())