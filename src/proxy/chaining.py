"""Proxy Chaining Module - Support for upstream proxies"""
import socket
import ssl
from typing import Optional, Dict, List
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class ProxyChain:
    def __init__(self):
        self.upstream_proxy: Optional[Dict[str, str]] = None
        self.proxy_chain: List[Dict[str, str]] = []
        self.auth_username: Optional[str] = None
        self.auth_password: Optional[str] = None

    def set_upstream_proxy(self, host: str, port: int,
                          username: Optional[str] = None,
                          password: Optional[str] = None,
                          proxy_type: str = "http"):
        self.upstream_proxy = {
            'host': host,
            'port': port,
            'type': proxy_type,
            'username': username,
            'password': password
        }
        self.auth_username = username
        self.auth_password = password
        logger.info(f"Upstream proxy configured: {host}:{port}")

    def add_to_chain(self, host: str, port: int,
                     username: Optional[str] = None,
                     password: Optional[str] = None):
        self.proxy_chain.append({
            'host': host,
            'port': port,
            'username': username,
            'password': password
        })

    def clear_chain(self):
        self.proxy_chain.clear()
        self.upstream_proxy = None

    def is_configured(self) -> bool:
        return self.upstream_proxy is not None or len(self.proxy_chain) > 0


class ProxyChainer:
    def __init__(self, chain: ProxyChain = None):
        self.chain = chain or ProxyChain()

    def forward_request(self, request_data: bytes,
                        target_host: str, target_port: int,
                        use_https: bool = False) -> bytes:
        if not self.chain.is_configured():
            return self._direct_connect(request_data, target_host, target_port, use_https)

        if self.chain.upstream_proxy:
            return self._forward_to_upstream(
                request_data, target_host, target_port, use_https
            )

        return self._direct_connect(request_data, target_host, target_port, use_https)

    def _direct_connect(self, request_data: bytes,
                        host: str, port: int, use_https: bool) -> bytes:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((host, port))

            if use_https:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.sendall(request_data)

            response = b''
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response += chunk
                if len(response) > 100000:
                    break

            sock.close()
            return response

        except Exception as e:
            logger.error(f"Direct connection failed: {e}")
            return b"HTTP/1.1 502 Bad Gateway\r\n\r\n"

    def _forward_to_upstream(self, request_data: bytes,
                             target_host: str, target_port: int,
                             use_https: bool) -> bytes:
        upstream = self.chain.upstream_proxy

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((upstream['host'], upstream['port']))

            if upstream['type'] == 'https':
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=upstream['host'])

            if upstream.get('username') and upstream.get('password'):
                import base64
                auth_str = f"{upstream['username']}:{upstream['password']}"
                auth_b64 = base64.b64encode(auth_str.encode()).decode()
                proxy_auth_header = f"Proxy-Authorization: Basic {auth_b64}\r\n"
            else:
                proxy_auth_header = ""

            if use_https:
                connect_request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n" \
                                  f"Host: {target_host}:{target_port}\r\n" \
                                  f"{proxy_auth_header}\r\n"
                sock.sendall(connect_request.encode())

                response = b''
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b'\r\n\r\n' in response:
                        break

                if b'200' not in response.split(b'\r\n')[0]:
                    return response

                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_side=False)
            else:
                host_line = f"http://{target_host}:{target_port}"
                proxy_request = f"GET {host_line} HTTP/1.1\r\n" \
                               f"Host: {target_host}\r\n" \
                               f"{proxy_auth_header}" \
                               f"Proxy-Connection: Keep-Alive\r\n\r\n"

                headers_end = request_data.decode('utf-8', errors='ignore').find('\r\n\r\n')
                if headers_end > 0:
                    body = request_data[headers_end + 4:]
                    proxy_request = f"GET {target_host}:{target_port} HTTP/1.1\r\n" \
                                   f"Host: {target_host}\r\n" \
                                   f"{proxy_auth_header}" \
                                   f"X-Forwarded-For: {target_host}\r\n\r\n"
                    if body:
                        proxy_request = proxy_request.encode() + body
                    else:
                        proxy_request = proxy_request.encode()
                else:
                    proxy_request = request_data

                sock.sendall(proxy_request)

            response = b''
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response += chunk
                if len(response) > 100000:
                    break

            sock.close()
            return response

        except Exception as e:
            logger.error(f"Upstream proxy failed: {e}")
            return b"HTTP/1.1 502 Bad Gateway\r\n\r\n"

    def handle_connect_via_proxy(self, client_socket: socket.socket,
                                  target_host: str, target_port: int) -> bool:
        if not self.chain.upstream_proxy:
            return False

        upstream = self.chain.upstream_proxy

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((upstream['host'], upstream['port']))

            if upstream['type'] == 'https':
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_side=False)

            connect_req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n" \
                         f"Host: {target_host}:{target_port}\r\n\r\n"

            if upstream.get('username') and upstream.get('password'):
                import base64
                auth_str = f"{upstream['username']}:{upstream['password']}"
                auth_b64 = base64.b64encode(auth_str.encode()).decode()
                connect_req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n" \
                             f"Host: {target_host}:{target_port}\r\n" \
                             f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n"

            sock.sendall(connect_req.encode())

            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b'\r\n\r\n' in response:
                    break

            if b'200' not in response.split(b'\r\n')[0]:
                client_socket.sendall(response)
                return False

            if upstream['type'] == 'https':
                context = ssl.create_default_context()
                client_ssl = context.wrap_socket(client_socket, server_side=True)
                server_ssl = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_NONE)
                self._relay_ssl(client_ssl, server_ssl)
            else:
                self._relay_sockets(sock, client_socket)

            return True

        except Exception as e:
            logger.error(f"CONNECT via upstream proxy failed: {e}")
            return False

    def _relay_ssl(self, client_ssl, server_ssl):
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(8192)
                    if not data:
                        break
                    dst.sendall(data)
            except:
                pass

        import threading
        t1 = threading.Thread(target=forward, args=(client_ssl, server_ssl))
        t2 = threading.Thread(target=forward, args=(server_ssl, client_ssl))
        t1.start()
        t2.start()
        t1.join(timeout=300)
        t2.join(timeout=1)

    def _relay_sockets(self, sock1, sock2):
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(8192)
                    if not data:
                        break
                    dst.sendall(data)
            except:
                pass

        import threading
        t1 = threading.Thread(target=forward, args=(sock1, sock2))
        t2 = threading.Thread(target=forward, args=(sock2, sock1))
        t1.start()
        t2.start()
        t1.join(timeout=300)
        t2.join(timeout=1)


if __name__ == '__main__':
    chain = ProxyChain()
    chain.set_upstream_proxy("proxy.example.com", 8080, username="user", password="pass")

    chainer = ProxyChainer(chain)
    print(f"Proxy chain configured: {chain.is_configured()}")
    print(f"Upstream: {chain.upstream_proxy['host']}:{chain.upstream_proxy['port']}")