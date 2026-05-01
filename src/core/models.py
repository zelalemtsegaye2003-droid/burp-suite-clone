"""HTTP Message Models"""
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from datetime import datetime
from enum import Enum


class MessageType(Enum):
    REQUEST = "request"
    RESPONSE = "response"


class Protocol(Enum):
    HTTP = "http"
    HTTPS = "https"


@dataclass
class HTTPMessage:
    id: Optional[int] = None
    type: MessageType = MessageType.REQUEST
    method: str = "GET"
    url: str = ""
    host: str = ""
    path: str = "/"
    protocol: Protocol = Protocol.HTTP
    status_code: Optional[int] = None
    status_text: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    timestamp: datetime = field(default_factory=datetime.now)
    response_time_ms: int = 0
    size: int = 0
    commented: bool = False
    highlighted: bool = False
    tags: List[str] = field(default_factory=list)

    @property
    def size_kb(self) -> float:
        return self.size / 1024

    @property
    def content_type(self) -> Optional[str]:
        return self.headers.get('Content-Type') or self.headers.get('content-type')

    @property
    def is_json(self) -> bool:
        ct = self.content_type or ""
        return 'application/json' in ct.lower()

    @property
    def is_html(self) -> bool:
        ct = self.content_type or ""
        return 'text/html' in ct.lower()

    @property
    def is_xml(self) -> bool:
        ct = self.content_type or ""
        return 'xml' in ct.lower()

    @property
    def body_text(self) -> Optional[str]:
        if self.body:
            try:
                return self.body.decode('utf-8', errors='replace')
            except:
                return self.body.decode('latin-1', errors='replace')
        return None

    @property
    def body_hex(self) -> str:
        if self.body:
            return self.body.hex()
        return ""

    def to_raw(self) -> str:
        lines = []
        if self.type == MessageType.REQUEST:
            lines.append(f"{self.method} {self.path} HTTP/1.1")
        else:
            lines.append(f"HTTP/1.1 {self.status_code} {self.status_text}")

        for key, value in self.headers.items():
            lines.append(f"{key}: {value}")

        lines.append("")
        if self.body_text:
            lines.append(self.body_text)

        return "\r\n".join(lines)


@dataclass
class HTTPRequest(HTTPMessage):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.type = MessageType.REQUEST


@dataclass
class HTTPResponse(HTTPMessage):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.type = MessageType.RESPONSE


@dataclass
class RequestResponsePair:
    id: Optional[int] = None
    request: Optional[HTTPMessage] = None
    response: Optional[HTTPMessage] = None
    notes: str = ""
    created_at: datetime = field(default_factory=datetime.now)

    @property
    def url(self) -> str:
        return self.request.url if self.request else ""

    @property
    def method(self) -> str:
        return self.request.method if self.request else ""

    @property
    def status_code(self) -> Optional[int]:
        return self.response.status_code if self.response else None

    @property
    def host(self) -> str:
        return self.request.host if self.request else ""


@dataclass
class FilterState:
    search_text: str = ""
    show_only_methods: List[str] = field(default_factory=list)
    show_only_status: List[int] = field(default_factory=list)
    show_only_hosts: List[str] = field(default_factory=list)
    show_only_types: List[str] = field(default_factory=list)
    show_only_mime: List[str] = field(default_factory=list)
    show_commented: bool = True
    show_highlighted: bool = True
    show_only_scope: bool = False
    scope_urls: List[str] = field(default_factory=list)


if __name__ == '__main__':
    req = HTTPRequest(
        method="GET",
        url="https://example.com/api/data",
        host="example.com",
        path="/api/data",
        protocol=Protocol.HTTPS,
        headers={"Accept": "application/json", "User-Agent": "BurpClone"}
    )
    print(req.to_raw())
    print(f"\nContent-Type: {req.content_type}")
    print(f"Is JSON: {req.is_json}")