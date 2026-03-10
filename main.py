import asyncio
import socket
import ssl



async def process_ssl_stream(source_socket, destination_socket, decrypt_sslobj, decrypt_in_bio, encrypt_sslobj, encrypt_out_bio, direction):
    """
    Flow:
    Raw Encrypted (from source) -> [decrypt in bio] -> [decrypt SSLObj] -> Plaintext
    Plaintext -> [encrypt SSLObj] -> [encrypt out bio] -> Raw Encrypted (Destination)
    """
    loop = asyncio.get_running_loop()
    try:
        while True:
            raw_encrypted = await loop.sock_recv(source_socket, 8192)
            if not raw_encrypted:
                 break
            

            decrypt_in_bio.write(raw_encrypted)

            while True:
                try:
                    plaintext = decrypt_sslobj.read(8192)
                    if not plaintext:
                         break
                    
                    print(f"[{direction}] Decrypted Content: {plaintext[:50]}")
                    
                    encrypt_sslobj.write(plaintext) 
                    
                    to_send = encrypt_out_bio.read()
                    if to_send:
                        await loop.sock_sendall(destination_socket, to_send)
                        
                except ssl.SSLWantReadError:
                    break
    except Exception as e:
        print(f"Error in {direction}: {e}")



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



async def handle_client(client_socket):
    loop = asyncio.get_running_loop()
    target_socket = None
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

        # connecting to target
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.setblocking(False)
        await loop.sock_connect(target_socket, (target_host, target_port))
        
        await loop.sock_sendall(client_socket, b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # starting SSL handshakes with both client and target
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        client_context.load_cert_chain("server.crt", "server.key")

        # SSLObject configuration for the client connection
        incoming_client = ssl.MemoryBIO()
        outgoing_client = ssl.MemoryBIO()
        sslobj_client = client_context.wrap_bio(incoming_client, outgoing_client, server_side=True)
        await do_ssl_handshake(client_socket, sslobj_client, incoming_client, outgoing_client)

        # SSLObject configuration for the target connection
        target_context = ssl.create_default_context()
        incoming_target = ssl.MemoryBIO()
        outgoing_target = ssl.MemoryBIO()
        sslobj_target = target_context.wrap_bio(incoming_target, outgoing_target, server_side=False, server_hostname=target_host)
        await do_ssl_handshake(target_socket, sslobj_target, incoming_target, outgoing_target)

        print("[*] Both Handshakes complete!")

        # start processing data in both directions
        await asyncio.gather(
            process_ssl_stream(client_socket, target_socket, sslobj_client, incoming_client, sslobj_target, outgoing_target, "Client->Target"),
            process_ssl_stream(target_socket, client_socket, sslobj_target, incoming_target, sslobj_client, outgoing_client, "Target->Client")
        )

    except Exception as e:
        print(f"[!] Handle Client Error: {e}")
    finally:
        client_socket.close()
        if target_socket:
            target_socket.close()



async def start_proxy():
    loop = asyncio.get_running_loop()

    listen_port = 4443
    #TLS config
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", listen_port))
    server.listen(100)
    server.setblocking(False)
    print(f"[*] Proxy listening on port {listen_port}")

    while True:
        client_socket, client_address = await loop.sock_accept(server)
        print(f"[*] Accepted connection from {client_address}")
        client_handler = asyncio.create_task(handle_client(client_socket))
        


if __name__ == "__main__":
    asyncio.run(start_proxy())