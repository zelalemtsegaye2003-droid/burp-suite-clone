"""Interceptor Module - Pause, Modify, Forward HTTP messages"""
from typing import Optional, Callable, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import threading
import logging
from .server import ProxyServer

logger = logging.getLogger(__name__)


class InterceptState(Enum):
    OFF = "off"
    ON = "on"
    BREAK_ON_SERVICE_ERROR = "break_on_service_error"


@dataclass
class InterceptedRequest:
    id: str
    timestamp: datetime = field(default_factory=datetime.now)
    raw_request: bytes = b""
    method: str = ""
    url: str = ""
    headers: dict = field(default_factory=dict)
    body: Optional[bytes] = None
    client_socket = None
    target_host: str = ""
    target_port: int = 80
    is_https: bool = False
    modified: bool = False

    def get_raw(self) -> bytes:
        if self.modified:
            return self._build_modified_request()
        return self.raw_request

    def _build_modified_request(self) -> bytes:
        lines = []
        lines.append(f"{self.method} {self.url} HTTP/1.1")
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        raw = "\r\n".join(lines).encode()
        if self.body:
            raw += self.body
        return raw

    def set_body(self, body: bytes):
        self.body = body
        self.modified = True

    def set_header(self, key: str, value: str):
        self.headers[key] = value
        self.modified = True

    def remove_header(self, key: str):
        if key in self.headers:
            del self.headers[key]
            self.modified = True


class RequestInterceptor:
    def __init__(self, proxy: ProxyServer = None):
        self.proxy = proxy
        self.state = InterceptState.OFF
        self.pending_requests: List[InterceptedRequest] = []
        self.lock = threading.Lock()
        self.request_callback: Optional[Callable] = None
        self.response_callback: Optional[Callable] = None
        self._callbacks_enabled = True

    def set_state(self, state: InterceptState):
        self.state = state
        logger.info(f"Intercept state: {state.value}")

        if self.proxy:
            self.proxy.set_intercept_mode(state != InterceptState.OFF)

    def is_intercepting(self) -> bool:
        return self.state != InterceptState.OFF

    def intercept_request(self, raw_request: bytes, method: str, url: str,
                         headers: dict, body: Optional[bytes],
                         client_socket, host: str, port: int, is_https: bool) -> Optional[InterceptedRequest]:
        if not self.is_intercepting():
            return None

        from . import FilterManager
        fm = FilterManager()
        allow, _ = fm.should_allow_request(method, url, host)
        if not allow:
            return None

        intercept_req = InterceptedRequest(
            id=f"{datetime.now().timestamp()}",
            raw_request=raw_request,
            method=method,
            url=url,
            headers=headers.copy(),
            body=body,
            client_socket=client_socket,
            target_host=host,
            target_port=port,
            is_https=is_https
        )

        with self.lock:
            self.pending_requests.append(intercept_req)

        if self.request_callback and self._callbacks_enabled:
            self._callbacks_enabled = False
            try:
                self.request_callback(intercept_req)
            finally:
                self._callbacks_enabled = True

        return intercept_req

    def get_pending(self) -> List[InterceptedRequest]:
        with self.lock:
            return self.pending_requests.copy()

    def drop_request(self, request_id: str) -> bool:
        with self.lock:
            for req in self.pending_requests:
                if req.id == request_id:
                    try:
                        req.client_socket.close()
                    except:
                        pass
                    self.pending_requests.remove(req)
                    logger.info(f"Dropped request: {request_id}")
                    return True
        return False

    def forward_request(self, request_id: str) -> bool:
        with self.lock:
            intercept_req = None
            for req in self.pending_requests:
                if req.id == request_id:
                    intercept_req = req
                    break

            if not intercept_req:
                return False

            try:
                import socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.settimeout(30)
                server_socket.connect((intercept_req.target_host, intercept_req.target_port))

                raw_request = intercept_req.get_raw()
                server_socket.sendall(raw_request)

                response = b''
                while True:
                    chunk = server_socket.recv(8192)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 100000:
                        break

                server_socket.close()

                intercept_req.client_socket.sendall(response)
                intercept_req.client_socket.close()

                self.pending_requests.remove(intercept_req)
                logger.info(f"Forwarded request: {request_id}")
                return True

            except Exception as e:
                logger.error(f"Error forwarding request: {e}")
                try:
                    intercept_req.client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    intercept_req.client_socket.close()
                except:
                    pass
                if intercept_req in self.pending_requests:
                    self.pending_requests.remove(intercept_req)
                return False

    def modify_and_forward(self, request_id: str, method: str = None,
                          url: str = None, headers: dict = None,
                          body: bytes = None) -> bool:
        with self.lock:
            for req in self.pending_requests:
                if req.id == request_id:
                    if method:
                        req.method = method
                    if url:
                        req.url = url
                    if headers:
                        req.headers.update(headers)
                    if body is not None:
                        req.body = body
                    req.modified = True

                    return self.forward_request(request_id)
        return False

    def on_request(self, callback: Callable):
        self.request_callback = callback

    def on_response(self, callback: Callable):
        self.response_callback = callback


class ResponseInterceptor:
    def __init__(self):
        self.enabled = False
        self.pending_responses: List = []
        self.lock = threading.Lock()

    def set_enabled(self, enabled: bool):
        self.enabled = enabled

    def intercept_response(self, request_id: str, raw_response: bytes,
                         status_code: int, headers: dict, body: bytes):
        if not self.enabled:
            return None

        with self.lock:
            self.pending_responses.append({
                'request_id': request_id,
                'raw_response': raw_response,
                'status_code': status_code,
                'headers': headers,
                'body': body
            })

        return self.pending_responses[-1]


if __name__ == '__main__':
    interceptor = RequestInterceptor()
    interceptor.set_state(InterceptState.ON)
    print(f"Intercepting: {interceptor.is_intercepting()}")