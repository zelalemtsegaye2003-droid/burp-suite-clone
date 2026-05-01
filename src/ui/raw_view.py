"""Raw View for HTTP Messages"""
from typing import Optional, Dict, List
from dataclasses import dataclass
from ..core.models import HTTPMessage, MessageType
import json


@dataclass
class RenderOptions:
    show_line_numbers: bool = True
    colorize: bool = True
    max_body_length: int = 50000
    word_wrap: bool = False
    highlight_syntax: bool = True


class RawViewRenderer:
    COLORS = {
        'reset': '\033[0m',
        'bold': '\033[1m',
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'gray': '\033[90m',
        'method': '\033[92m',
        'status_2xx': '\033[92m',
        'status_3xx': '\033[93m',
        'status_4xx': '\033[91m',
        'status_5xx': '\033[91m',
        'header': '\033[94m',
        'body_json': '\033[92m',
        'body_html': '\033[93m',
    }

    def __init__(self, options: RenderOptions = None):
        self.options = options or RenderOptions()

    def render(self, message: HTTPMessage) -> str:
        if message.type == MessageType.REQUEST:
            return self.render_request(message)
        else:
            return self.render_response(message)

    def render_request(self, req: HTTPMessage) -> str:
        lines = []

        if self.options.show_line_numbers:
            lines.append(self._header_line("REQUEST", req.id))
        else:
            lines.append("=" * 60)
            lines.append(f"Request #{req.id}")
            lines.append("=" * 60)

        lines.append("")
        self._append_method_line(req, lines)
        lines.append("")

        if self.options.show_line_numbers:
            lines.append(self._header_line("HEADERS"))
        self._append_headers(req.headers, lines)
        lines.append("")

        if req.body:
            self._append_body(req, lines)
        else:
            lines.append("[No Body]")

        return "\n".join(lines)

    def render_response(self, resp: HTTPMessage) -> str:
        lines = []

        lines.append("=" * 60)
        lines.append(f"Response")
        lines.append("=" * 60)

        lines.append("")
        self._append_status_line(resp, lines)
        lines.append("")

        if self.options.show_line_numbers:
            lines.append(self._header_line("HEADERS"))
        self._append_headers(resp.headers, lines)
        lines.append("")

        if resp.body:
            self._append_body(resp, lines)
        else:
            lines.append("[No Body]")

        return "\n".join(lines)

    def _header_line(self, text: str, num: int = None) -> str:
        if self.options.colorize:
            bold = self.COLORS['bold']
            reset = self.COLORS['reset']
            line = f"{bold}{'─' * 40} {text} {'─' * 40}{reset}"
            if num:
                line += f" #{num}"
            return line
        else:
            line = f"--- {text} ---"
            if num:
                line += f" #{num}"
            return line

    def _append_method_line(self, req: HTTPMessage, lines: List[str]):
        method_color = self.COLORS['method'] if self.options.colorize else ""
        reset = self.COLORS['reset'] if self.options.colorize else ""

        url = f"{req.protocol.value}://{req.host}{req.path}"
        line = f"{method_color}{req.method}{reset} {url} HTTP/1.1"
        lines.append(line)

        lines.append(f"Host: {req.host}")

    def _append_status_line(self, resp: HTTPMessage, lines: List[str]):
        status_color = self._get_status_color(resp.status_code)
        status_text = status_color if self.options.colorize else ""
        reset = self.COLORS['reset'] if self.options.colorize else ""

        line = f"HTTP/1.1 {status_color}{resp.status_code}{reset} {resp.status_text}"
        lines.append(line)

    def _get_status_color(self, status_code: int) -> str:
        if 100 <= status_code < 200:
            return self.COLORS['gray']
        elif 200 <= status_code < 300:
            return self.COLORS['status_2xx']
        elif 300 <= status_code < 400:
            return self.COLORS['status_3xx']
        elif 400 <= status_code < 500:
            return self.COLORS['status_4xx']
        else:
            return self.COLORS['status_5xx']

    def _append_headers(self, headers: Dict[str, str], lines: List[str]):
        header_color = self.COLORS['header'] if self.options.colorize else ""
        reset = self.COLORS['reset'] if self.options.colorize else ""

        for key, value in headers.items():
            lines.append(f"{header_color}{key}:{reset} {value}")

    def _append_body(self, message: HTTPMessage, lines: List[str]):
        body_text = message.body_text

        if not body_text:
            lines.append(f"[Binary body: {len(message.body)} bytes]")
            return

        if len(body_text) > self.options.max_body_length:
            body_text = body_text[:self.options.max_body_length]
            lines.append(f"[Body truncated - showing first {self.options.max_body_length} chars]")
        else:
            lines.append(f"[Body: {len(body_text)} bytes]")

        lines.append("")
        lines.append("-" * 40)

        if self.options.highlight_syntax:
            body_text = self._highlight_body(body_text, message)

        if self.options.word_wrap:
            body_text = self._word_wrap(body_text)

        lines.append(body_text)
        lines.append("-" * 40)

    def _highlight_body(self, body: str, message: HTTPMessage) -> str:
        if message.is_json:
            try:
                parsed = json.loads(body)
                return json.dumps(parsed, indent=2)
            except:
                pass
        return body

    def _word_wrap(self, text: str, width: int = 80) -> str:
        words = text.split()
        lines = []
        current_line = []
        for word in words:
            if len(" ".join(current_line)) + len(word) + 1 > width:
                if current_line:
                    lines.append(" ".join(current_line))
                    current_line = []
            current_line.append(word)
        if current_line:
            lines.append(" ".join(current_line))
        return "\n".join(lines)


class RawViewEditor:
    def __init__(self):
        pass

    def edit_message(self, message: HTTPMessage, new_raw: str) -> HTTPMessage:
        lines = new_raw.split('\r\n') if '\r\n' in new_raw else new_raw.split('\n')

        if message.type == MessageType.REQUEST:
            return self._parse_request(lines, message.id)
        else:
            return self._parse_response(lines)

    def _parse_request(self, lines: List[str], existing_id: int = None) -> HTTPMessage:
        if not lines:
            raise ValueError("Empty request")

        request_line = lines[0].split()
        if len(request_line) < 3:
            raise ValueError("Invalid request line")

        method = request_line[0]
        url = request_line[1]
        version = request_line[2] if len(request_line) > 2 else "HTTP/1.1"

        headers = {}
        body_start = 0

        for i, line in enumerate(lines[1:], 1):
            if not line.strip():
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        body = None
        if body_start < len(lines):
            body_text = '\n'.join(lines[body_start:])
            if body_text.strip():
                body = body_text.encode()

        from ..core.models import Protocol
        host = headers.get('Host', '')

        protocol = Protocol.HTTPS if url.startswith('https') else Protocol.HTTP

        path = url
        if '://' in url:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query

        return HTTPMessage(
            id=existing_id,
            type=MessageType.REQUEST,
            method=method,
            url=url,
            host=host,
            path=path,
            protocol=protocol,
            headers=headers,
            body=body
        )

    def _parse_response(self, lines: List[str]) -> HTTPMessage:
        if not lines:
            raise ValueError("Empty response")

        status_line = lines[0].split()
        if len(status_line) < 2:
            raise ValueError("Invalid status line")

        version = status_line[0]
        status_code = int(status_line[1])
        status_text = " ".join(status_line[2:]) if len(status_line) > 2 else ""

        headers = {}
        body_start = 0

        for i, line in enumerate(lines[1:], 1):
            if not line.strip():
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        body = None
        if body_start < len(lines):
            body_text = '\n'.join(lines[body_start:])
            if body_text.strip():
                body = body_text.encode()

        return HTTPMessage(
            type=MessageType.RESPONSE,
            status_code=status_code,
            status_text=status_text,
            headers=headers,
            body=body
        )


class MessageViewer:
    def __init__(self):
        self.renderer = RawViewRenderer()
        self.editor = RawViewEditor()

    def view(self, message: HTTPMessage, options: RenderOptions = None) -> str:
        if options:
            self.renderer.options = options
        return self.renderer.render(message)

    def edit(self, message: HTTPMessage, new_raw: str) -> HTTPMessage:
        return self.editor.edit_message(message, new_raw)

    def view_diff(self, old: HTTPMessage, new: HTTPMessage) -> str:
        old_raw = old.to_raw()
        new_raw = new.to_raw()

        from difflib import unified_diff
        diff = list(unified_diff(
            old_raw.splitlines(),
            new_raw.splitlines(),
            lineterm='',
            fromfile='original',
            tofile='modified'
        ))

        return "\n".join(diff)


if __name__ == '__main__':
    from src.core.models import HTTPMessage, MessageType, Protocol

    msg = HTTPMessage(
        id=1,
        type=MessageType.REQUEST,
        method="GET",
        url="http://example.com/api/data",
        host="example.com",
        path="/api/data",
        protocol=Protocol.HTTP,
        headers={
            "Accept": "application/json",
            "User-Agent": "BurpClone/1.0",
            "Authorization": "Bearer token123"
        },
        body=b'{"key": "value"}'
    )

    viewer = MessageViewer()
    print(viewer.view(msg))