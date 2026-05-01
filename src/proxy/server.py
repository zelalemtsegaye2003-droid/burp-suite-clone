"""HTTP Proxy Server"""
import socket
import threading
import logging
from datetime import datetime
from typing import Optional, Dict, Any

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ProxyServer:
    def __init__(self, host: str = '127.0.0.1', port: int = 8080, db_path: str = None):
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.intercept_mode = False
        self.request_callback = None
        self.response_callback = None
        self.db = None
        if db_path:
            from .database import ProxyDatabase
            self.db = ProxyDatabase(db_path)

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        self.running = True

        logger.info(f"Proxy server started on {self.host}:{self.port}")

        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                thread.daemon = True
                thread.start()
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {e}")

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("Proxy server stopped")

    def handle_client(self, client_socket: socket.socket, client_address):
        try:
            request = client_socket.recv(4096)
            if not request:
                client_socket.close()
                return

            request_str = request.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')

            if not lines:
                client_socket.close()
                return

            request_line = lines[0]
            parts = request_line.split()

            if len(parts) < 3:
                client_socket.close()
                return

            method, url, version = parts[0], parts[1], parts[2]

            if method == 'CONNECT':
                self.handle_connect(client_socket, url)
            else:
                self.handle_http_request(client_socket, request_str, method, url)

        except Exception as e:
            logger.error(f"Error handling client: {e}")
            client_socket.close()

    def handle_connect(self, client_socket: socket.socket, url: str):
        host, port = url.split(':') if ':' in url else (url, 443)
        port = int(port) if ':' in url else 443

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((host, port))

            client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

            self.relay_traffic(client_socket, server_socket)
        except Exception as e:
            logger.error(f"CONNECT error: {e}")
            client_socket.close()

    def handle_http_request(self, client_socket: socket.socket,
                            request_str: str, method: str, url: str):
        headers, body = self.parse_request(request_str)

        target_host = headers.get('Host', '')
        target_port = 80

        if '://' in url:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            target_host = parsed.hostname or target_host
            target_port = parsed.port or 80

        proxy_request_data = {
            'method': method,
            'url': url,
            'headers': headers,
            'body': body,
            'timestamp': datetime.now().isoformat(),
            'client': client_socket.getpeername()
        }

        if self.request_callback:
            self.request_callback(proxy_request_data)

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((target_host, target_port))
            server_socket.sendall(request_str.encode())

            response = b''
            while True:
                chunk = server_socket.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 100000:
                    break

            server_socket.close()

            proxy_response_data = {
                'status_code': 200,
                'headers': {},
                'body': response,
                'timestamp': datetime.now().isoformat()
            }

            if self.response_callback:
                self.response_callback(proxy_response_data)

            client_socket.sendall(response)

        except Exception as e:
            logger.error(f"Error forwarding request: {e}")
            error_response = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
            client_socket.sendall(error_response)

        client_socket.close()

    def parse_request(self, request_str: str) -> tuple[Dict[str, str], Optional[bytes]]:
        lines = request_str.split('\r\n')
        headers = {}

        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        body = None
        if body_start < len(lines):
            body_str = '\r\n'.join(lines[body_start:])
            body = body_str.encode() if body_str else None

        return headers, body

    def relay_traffic(self, client_socket: socket.socket, server_socket: socket.socket):
        def forward(source, destination):
            try:
                while True:
                    data = source.recv(4096)
                    if not data:
                        break
                    destination.sendall(data)
            except:
                pass

        t1 = threading.Thread(target=forward, args=(client_socket, server_socket))
        t2 = threading.Thread(target=forward, args=(server_socket, client_socket))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        client_socket.close()
        server_socket.close()

    def set_intercept_mode(self, enabled: bool):
        self.intercept_mode = enabled

    def on_request(self, callback):
        self.request_callback = callback

    def on_response(self, callback):
        self.response_callback = callback


def run_proxy(host: str = '127.0.0.1', port: int = 8080):
    server = ProxyServer(host, port)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()


if __name__ == '__main__':
    run_proxy()