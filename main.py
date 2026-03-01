import asyncio
import socket
import ssl

async def handle_client(client_socket):
    loop = asyncio.get_running_loop()
    secure_target_socket = None

    try:
        client_socket.setblocking(False) 
        
        initial_request = await loop.sock_recv(client_socket, 4096)
        initial_request = repr(initial_request)
    
        first_line = initial_request.split('\n')[0]
        if "CONNECT" in first_line:
            target_full = first_line.split(' ')[1]
            target_host, target_port = target_full.split(':')
            target_port = int(target_port)
            print(f"[*] target host: {target_host} target port: {target_port}")
            
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.setblocking(False) 
            
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH) 
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED           
            
            secure_target_socket = context.wrap_socket(target_socket, server_hostname=target_host)
            await loop.sock_connect(secure_target_socket, (target_host, target_port))

            await loop.sock_sendall(client_socket, b"HTTP/1.1 200 Connection Established\r\n\r\n")

            while True:
                client_data = await loop.sock_recv(client_socket, 4096)
                if len(client_data) > 0:
                    print(repr(client_data))
                    print(f"[*] Forwarding {len(client_data)} bytes to target")
                    await loop.sock_sendall(secure_target_socket, client_data)
                
                target_data = await loop.sock_recv(secure_target_socket, 4096)
                if len(target_data) > 0:
                    print(f"[*] Sending {len(target_data)} bytes back to client")
                    await loop.sock_sendall(client_socket, target_data)
        else:
            print(f"could find connection request")        
    except Exception as e:
        print(f"[!] Error: {e}")

    finally:
        client_socket.close()
        if secure_target_socket is not None:
            secure_target_socket.close()



async def start_proxy():
    loop = asyncio.get_running_loop()

    listen_port = 4443
    #TLS config
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setblocking(False) 
    server.bind(("localhost", listen_port))
    server.listen(5)
    print(f"[*] Proxy listening on port {listen_port}")

    while True:
        client_socket, client_address = await loop.sock_accept(server)
        print(f"[*] Accepted connection from {client_address}")
        # wrapping with TLS
        conn = server_context.wrap_socket(client_socket, server_side=True)
        client_handler = asyncio.create_task(handle_client(conn))


if __name__ == "__main__":
    asyncio.run(start_proxy())
