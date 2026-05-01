"""Message Viewer - Unified view for HTTP messages"""
from enum import Enum
from typing import Optional
from ..core.models import HTTPMessage, MessageType
from .raw_view import RawViewRenderer, MessageViewer as RawViewer
from .parsed_view import ParsedViewRenderer, RequestParser, ResponseParser
from .hex_view import HexViewRenderer, HexViewer


class ViewMode(Enum):
    RAW = "raw"
    PARSED = "parsed"
    HEX = "hex"
    HEADERS = "headers"
    BODY = "body"


class MessageViewer:
    def __init__(self):
        self.raw_renderer = RawViewRenderer()
        self.raw_viewer = RawViewer()
        self.parsed_renderer = ParsedViewRenderer()
        self.hex_renderer = HexViewRenderer()
        self.hex_viewer = HexViewer()
        self.req_parser = RequestParser()
        self.resp_parser = ResponseParser()

    def view(self, message: HTTPMessage, mode: ViewMode = ViewMode.RAW) -> str:
        if mode == ViewMode.RAW:
            return self.raw_renderer.render(message)
        elif mode == ViewMode.PARSED:
            return self.parsed_renderer.render(message)
        elif mode == ViewMode.HEX:
            return self.hex_renderer.render_message(message)
        elif mode == ViewMode.HEADERS:
            return self._render_headers(message)
        elif mode == ViewMode.BODY:
            return self._render_body(message)
        else:
            return self.raw_renderer.render(message)

    def _render_headers(self, message: HTTPMessage) -> str:
        lines = []
        lines.append("Headers View")
        lines.append("=" * 60)

        if message.type == MessageType.REQUEST:
            lines.append(f"Request-Line: {message.method} {message.path} HTTP/1.1")
        else:
            lines.append(f"Status-Line: HTTP/1.1 {message.status_code} {message.status_text}")

        lines.append("")
        for key, value in message.headers.items():
            lines.append(f"{key}: {value}")

        return "\n".join(lines)

    def _render_body(self, message: HTTPMessage) -> str:
        if not message.body:
            return "(no body)"

        if message.is_json:
            try:
                parsed = message.body_text
                obj = json.loads(parsed)
                return json.dumps(obj, indent=2)
            except:
                pass

        return message.body_text or message.body.hex()

    def edit(self, message: HTTPMessage, new_raw: str) -> HTTPMessage:
        return self.raw_viewer.edit(message, new_raw)

    def diff(self, old: HTTPMessage, new: HTTPMessage) -> str:
        return self.raw_viewer.view_diff(old, new)


import json

if __name__ == '__main__':
    from src.core.models import HTTPMessage, MessageType, Protocol

    req = HTTPMessage(
        id=1,
        type=MessageType.REQUEST,
        method="POST",
        url="http://example.com/api/login",
        host="example.com",
        path="/api/login",
        protocol=Protocol.HTTP,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "BurpClone/1.0"
        },
        body=b'{"username": "admin", "password": "secret123"}'
    )

    viewer = MessageViewer()

    print("=" * 60)
    print("RAW VIEW")
    print("=" * 60)
    print(viewer.view(req, ViewMode.RAW))

    print("\n" + "=" * 60)
    print("PARSED VIEW")
    print("=" * 60)
    print(viewer.view(req, ViewMode.PARSED))

    print("\n" + "=" * 60)
    print("HEX VIEW")
    print("=" * 60)
    print(viewer.view(req, ViewMode.HEX))