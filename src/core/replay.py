"""Request Replay Module"""
from typing import Optional, Dict, Callable, List
from dataclasses import dataclass
from datetime import datetime
import time
import socket
import ssl
from ..core.models import HTTPMessage, MessageType
import logging

logger = logging.getLogger('replay')


class ReplayResult:
    def __init__(self, success: bool, status_code: int = 0,
                 response_body: bytes = b"", response_headers: Dict = None,
                 error: str = "", time_ms: int = 0):
        self.success = success
        self.status_code = status_code
        self.response_body = response_body
        self.response_headers = response_headers or {}
        self.error = error
        self.time_ms = time_ms


class RequestReplayer:
    def __init__(self):
        self.timeout = 30
        self.follow_redirects = True
        self.max_redirects = 5

    def replay(self, message: HTTPMessage) -> ReplayResult:
        start_time = time.time()

        try:
            if message.type != MessageType.REQUEST:
                return ReplayResult(False, error="Not a request message")

            host = message.host
            port = 443 if message.protocol.value == 'https' else 80

            if ':' in host:
                parts = host.split(':')
                host = parts[0]
                port = int(parts[1])

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if message.protocol.value == 'https':
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)
            else:
                sock.connect((host, port))

            request = self._build_request(message)
            sock.sendall(request)

            response = self._receive_response(sock)
            sock.close()

            time_ms = int((time.time() - start_time) * 1000)

            if response:
                status_line = response.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                status_parts = status_line.split(' ')
                status_code = int(status_parts[1]) if len(status_parts) > 1 else 0

                headers, body = self._parse_response(response)

                return ReplayResult(
                    success=True,
                    status_code=status_code,
                    response_body=body,
                    response_headers=headers,
                    time_ms=time_ms
                )
            else:
                return ReplayResult(False, error="No response received", time_ms=time_ms)

        except Exception as e:
            logger.error(f"Replay failed: {e}")
            time_ms = int((time.time() - start_time) * 1000)
            return ReplayResult(False, error=str(e), time_ms=time_ms)

    def _build_request(self, message: HTTPMessage) -> bytes:
        lines = []
        lines.append(f"{message.method} {message.path} HTTP/1.1")

        has_host = any(h.lower() == 'host' for h in message.headers.keys())
        if not has_host:
            lines.append(f"Host: {message.host}")

        for key, value in message.headers.items():
            lines.append(f"{key}: {value}")

        lines.append("Connection: close")
        lines.append("")

        request = "\r\n".join(lines).encode()

        if message.body:
            request += message.body

        return request

    def _receive_response(self, sock: socket.socket) -> bytes:
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 10 * 1024 * 1024:
                    break
            except socket.timeout:
                break
        return response

    def _parse_response(self, response: bytes) -> tuple[Dict, bytes]:
        headers = {}
        body = b""

        parts = response.split(b'\r\n\r\n', 1)
        if len(parts) == 2:
            header_part, body = parts

            header_lines = header_part.decode('utf-8', errors='ignore').split('\r\n')
            for line in header_lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
        else:
            body = response

        return headers, body


class BatchReplayer:
    def __init__(self, replayer: RequestReplayer = None):
        self.replayer = replayer or RequestReplayer()
        self.results: List[ReplayResult] = []
        self.progress_callback: Optional[Callable] = None

    def replay_multiple(self, messages: List[HTTPMessage]) -> List[ReplayResult]:
        results = []
        total = len(messages)

        for i, msg in enumerate(messages):
            result = self.replayer.replay(msg)
            results.append(result)

            if self.progress_callback:
                self.progress_callback(i + 1, total, result)

        self.results = results
        return results

    def replay_with_variations(self, message: HTTPMessage,
                               variations: List[Dict]) -> List[ReplayResult]:
        results = []

        for vars in variations:
            modified = HTTPMessage(
                id=message.id,
                type=message.type,
                method=vars.get('method', message.method),
                url=vars.get('url', message.url),
                host=vars.get('host', message.host),
                path=vars.get('path', message.path),
                protocol=message.protocol,
                headers=message.headers.copy(),
                body=vars.get('body', message.body)
            )

            result = self.replayer.replay(modified)
            results.append(result)

        return results


class SessionReplayer:
    def __init__(self):
        self.replayer = RequestReplayer()
        self.cookies: Dict[str, str] = {}

    def replay_with_session(self, message: HTTPMessage) -> ReplayResult:
        if 'Cookie' in message.headers:
            cookie_str = message.headers['Cookie']
            for part in cookie_str.split(';'):
                if '=' in part:
                    k, v = part.strip().split('=', 1)
                    self.cookies[k] = v

        if self.cookies:
            cookie_header = '; '.join(f"{k}={v}" for k, v in self.cookies.items())
            message.headers['Cookie'] = cookie_header

        result = self.replayer.replay(message)

        if result.success and result.response_headers:
            set_cookie = result.response_headers.get('Set-Cookie', '')
            if set_cookie:
                parts = set_cookie.split(';')
                if parts:
                    kv = parts[0].split('=')
                    if len(kv) == 2:
                        self.cookies[kv[0]] = kv[1]

        return result

    def clear_session(self):
        self.cookies.clear()


if __name__ == '__main__':
    from src.core.models import HTTPMessage, MessageType, Protocol

    req = HTTPMessage(
        type=MessageType.REQUEST,
        method="GET",
        url="http://httpbin.org/get",
        host="httpbin.org",
        path="/get",
        protocol=Protocol.HTTP,
        headers={"User-Agent": "BurpClone"}
    )

    replayer = RequestReplayer()
    result = replayer.replay(req)

    print(f"Success: {result.success}")
    print(f"Status: {result.status_code}")
    print(f"Time: {result.time_ms}ms")
    if result.error:
        print(f"Error: {result.error}")