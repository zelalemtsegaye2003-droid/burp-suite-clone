"""HTTPS Proxy with SSL Interception"""
import socket
import ssl
import threading
import logging
from datetime import datetime
from typing import Optional, Dict, Callable
from .ssl_cert import SSLCertGenerator
from .database import ProxyDatabase
from .filter import FilterManager
from .chaining import ProxyChain, ProxyChainer

try:
    from ..scanner.passive import PassiveScanner
    HAS_PASSIVE_SCANNER = True
except:
    HAS_PASSIVE_SCANNER = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class HTTPSProxy:
    def __init__(self, host: str = '127.0.0.1', port: int = 8080,
                 db_path: str = None, cert_gen: SSLCertGenerator = None,
                 filter_manager: FilterManager = None):
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.intercept_mode = False
        self.request_callback: Optional[Callable] = None
        self.response_callback: Optional[Callable] = None
        self.db: Optional[ProxyDatabase] = None
        self.cert_gen = cert_gen or SSLCertGenerator()
        self.cert_gen.generate_ca()
        self.filter_manager = filter_manager or FilterManager()
        self.proxy_chain = ProxyChain()
        self.chainer = ProxyChainer(self.proxy_chain)
        self.passive_scanner = None
        if HAS_PASSIVE_SCANNER:
            self.passive_scanner = PassiveScanner()

        if db_path:
            self.db = ProxyDatabase(db_path)

        self.cert_cache: Dict[str, tuple] = {}

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        self.running = True

        logger.info(f"HTTPS Proxy started on {self.host}:{self.port}")

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
        logger.info("HTTPS Proxy stopped")

    def handle_client(self, client_socket: socket.socket, client_address):
        try:
            client_socket.settimeout(5)
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
            try:
                client_socket.close()
            except:
                pass

    def handle_connect(self, client_socket: socket.socket, url: str):
        host, port = url.split(':') if ':' in url else (url, 443)
        port = int(port) if ':' in url else 443

        logger.info(f"CONNECT request to {host}:{port}")

        if host not in self.cert_cache:
            cert_pem, key_pem = self.cert_gen.generate_cert(host)
            self.cert_cache[host] = (cert_pem, key_pem)

        cert_pem, key_pem = self.cert_cache[host]

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10)
            server_socket.connect((host, port))

            client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain_from_memory(cert_pem, key_pem)
            context.verify_mode = ssl.CERT_NONE

            client_ssl = context.wrap_socket(
                client_socket, server_side=True
            )

            server_ssl = ssl.wrap_socket(
                server_socket,
                cafile=None,
                cert_reqs=ssl.CERT_NONE
            )

            self.relay_https(client_ssl, server_ssl, host)

        except Exception as e:
            logger.error(f"CONNECT error: {e}")
            try:
                client_socket.close()
            except:
                pass

    def relay_https(self, client_ssl, server_ssl, host: str):
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(8192)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass

        t1 = threading.Thread(target=forward, args=(client_ssl, server_ssl))
        t2 = threading.Thread(target=forward, args=(server_ssl, client_ssl))
        t1.start()
        t2.start()
        t1.join(timeout=300)
        t2.join(timeout=1)

        try:
            client_ssl.close()
        except:
            pass
        try:
            server_ssl.close()
        except:
            pass

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

        allow, filter_reason = self.filter_manager.should_allow_request(
            method, url, target_host
        )
        if not allow:
            logger.info(f"Request blocked: {filter_reason}")
            client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            client_socket.close()
            return

        proxy_request_data = {
            'method': method,
            'url': url,
            'headers': headers,
            'body': body,
            'timestamp': datetime.now().isoformat(),
            'client': client_socket.getpeername(),
            'is_https': False
        }

        if self.request_callback:
            self.request_callback(proxy_request_data)

        if self.db:
            request_id = self.db.save_request(
                method, url, headers, body, target_host,
                url.split(target_host)[1] if target_host in url else '/'
            )

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(30)
            server_socket.connect((target_host, target_port))
            server_socket.sendall(request_str.encode())

            response = b''
            while True:
                chunk = server_socket.recv(8192)
                if not chunk:
                    break
                response += chunk
                if len(response) > 100000:
                    break

            server_socket.close()

            content_type = None
            for header in response.split(b'\r\n'):
                if header.lower().startswith(b'content-type:'):
                    content_type = header.decode('utf-8', errors='ignore').split(':', 1)[1].strip()
                    break

            status_code = 200
            if b'HTTP/' in response:
                status_line = response.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                parts = status_line.split(' ')
                if len(parts) >= 2:
                    try:
                        status_code = int(parts[1])
                    except:
                        pass

            allow_resp, filter_reason = self.filter_manager.should_allow_response(status_code, content_type)
            if not allow_resp:
                logger.info(f"Response blocked: {filter_reason} (status {status_code})")
                client_socket.sendall(b"HTTP/1.1 204 No Content\r\nX-Filtered: true\r\n\r\n")
                client_socket.close()
                return

            proxy_response_data = {
                'status_code': 200,
                'headers': {},
                'body': response,
                'timestamp': datetime.now().isoformat()
            }

            if self.response_callback:
                self.response_callback(proxy_response_data)

            if self.db and 'request_id' in locals():
                status_text = "OK"
                self.db.save_response(request_id, 200, status_text, {}, response)

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

    def set_intercept_mode(self, enabled: bool):
        self.intercept_mode = enabled

    def set_passive_scan(self, enabled: bool):
        if self.passive_scanner:
            self.passive_scanner.enabled = enabled
            logger.info(f"Passive scanner: {'enabled' if enabled else 'disabled'}")

    def get_passive_issues(self):
        if self.passive_scanner:
            return self.passive_scanner.get_issues()
        return []

    def get_passive_summary(self):
        if self.passive_scanner:
            return self.passive_scanner.get_summary()
        return {}

    def clear_passive_issues(self):
        if self.passive_scanner:
            self.passive_scanner.clear_issues()

    def _scan_with_passive(self, request_dict: Dict, response_dict: Dict = None):
        if not self.passive_scanner or not self.passive_scanner.enabled:
            return

        self.passive_scanner.scan_request(request_dict)

        if response_dict:
            self.passive_scanner.scan_response(request_dict, response_dict)

    def set_upstream_proxy(self, host: str, port: int,
                          username: Optional[str] = None,
                          password: Optional[str] = None,
                          proxy_type: str = "http"):
        self.proxy_chain.set_upstream_proxy(host, port, username, password, proxy_type)
        logger.info(f"Upstream proxy set: {host}:{port}")

    def on_request(self, callback: Callable):
        self.request_callback = callback

    def on_response(self, callback: Callable):
        self.response_callback = callback


def run_https_proxy(host: str = '127.0.0.1', port: int = 8080, db_path: str = None):
    proxy = HTTPSProxy(host, port, db_path)
    try:
        proxy.start()
    except KeyboardInterrupt:
        proxy.stop()


if __name__ == '__main__':
    run_https_proxy()