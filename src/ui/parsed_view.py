"""Parsed View for HTTP Messages - Headers, Params, Cookies"""
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from ..core.models import HTTPMessage, MessageType
from urllib.parse import parse_qs, urlparse, urlunparse
import json


@dataclass
class ParsedRequest:
    method: str
    url: str
    host: str
    path: str
    query_params: Dict[str, List[str]]
    headers: Dict[str, str]
    cookies: Dict[str, str]
    body: Optional[str]
    body_type: str
    form_params: Dict[str, List[str]]


@dataclass
class ParsedResponse:
    status_code: int
    status_text: str
    headers: Dict[str, str]
    cookies: Dict[str, str]
    body: Optional[str]
    body_type: str
    content_length: int
    encoding: str


class RequestParser:
    def parse(self, message: HTTPMessage) -> ParsedRequest:
        query_params = self._parse_query(message.path)
        headers = message.headers
        cookies = self._parse_cookies(headers.get('Cookie', ''))

        body = None
        body_type = 'none'
        form_params = {}

        if message.body:
            try:
                body = message.body.decode('utf-8', errors='replace')
            except:
                body = message.body.decode('latin-1', errors='replace')

            content_type = headers.get('Content-Type', headers.get('content-type', ''))

            if 'application/json' in content_type:
                body_type = 'json'
            elif 'application/x-www-form-urlencoded' in content_type:
                body_type = 'form'
                form_params = self._parse_form_data(body)
            elif 'text/' in content_type or 'xml' in content_type:
                body_type = 'text'
            else:
                body_type = 'binary'

        return ParsedRequest(
            method=message.method,
            url=message.url,
            host=message.host,
            path=message.path,
            query_params=query_params,
            headers=headers,
            cookies=cookies,
            body=body,
            body_type=body_type,
            form_params=form_params
        )

    def _parse_query(self, path: str) -> Dict[str, List[str]]:
        if '?' not in path:
            return {}

        query_string = path.split('?', 1)[1]
        try:
            parsed = parse_qs(query_string, keep_blank_values=True)
            return {k: v if len(v) > 1 else v[0] for k, v in parsed.items()}
        except:
            return {}

    def _parse_cookies(self, cookie_header: str) -> Dict[str, str]:
        if not cookie_header:
            return {}

        cookies = {}
        for part in cookie_header.split(';'):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                cookies[key.strip()] = value.strip()
        return cookies

    def _parse_form_data(self, body: str) -> Dict[str, List[str]]:
        try:
            parsed = parse_qs(body, keep_blank_values=True)
            return parsed
        except:
            return {}


class ResponseParser:
    def parse(self, message: HTTPMessage) -> ParsedResponse:
        headers = message.headers
        cookies = self._parse_set_cookie(headers)

        body = None
        body_type = 'none'
        content_length = 0
        encoding = 'utf-8'

        if message.body:
            content_length = len(message.body)

            content_type = headers.get('Content-Type', headers.get('content-type', ''))

            if 'application/json' in content_type:
                body_type = 'json'
                try:
                    body = message.body.decode('utf-8')
                except:
                    body = message.body.decode('latin-1')
            elif 'text/html' in content_type:
                body_type = 'html'
                encoding = self._detect_encoding(headers, message.body)
                try:
                    body = message.body.decode(encoding, errors='replace')
                except:
                    body = message.body.decode('utf-8', errors='replace')
            elif 'text/' in content_type or 'xml' in content_type:
                body_type = 'text'
                try:
                    body = message.body.decode('utf-8', errors='replace')
                except:
                    body = message.body.decode('latin-1', errors='replace')
            else:
                body_type = 'binary'

        return ParsedResponse(
            status_code=message.status_code or 0,
            status_text=message.status_text,
            headers=headers,
            cookies=cookies,
            body=body,
            body_type=body_type,
            content_length=content_length,
            encoding=encoding
        )

    def _parse_set_cookie(self, headers: Dict[str, str]) -> Dict[str, str]:
        cookies = {}
        set_cookie = headers.get('Set-Cookie', headers.get('set-cookie', ''))
        if set_cookie:
            parts = set_cookie.split(';')
            if parts:
                name_value = parts[0].strip()
                if '=' in name_value:
                    key, value = name_value.split('=', 1)
                    cookies[key.strip()] = value.strip()
        return cookies

    def _detect_encoding(self, headers: Dict[str, str], body: bytes) -> str:
        content_type = headers.get('Content-Type', '')
        if 'charset=' in content_type:
            encoding = content_type.split('charset=')[1].split(';')[0].strip()
            return encoding

        if body[:3] == b'\xef\xbb\xbf':
            return 'utf-8-sig'

        return 'utf-8'


class ParsedViewRenderer:
    def render(self, message: HTTPMessage) -> str:
        if message.type == MessageType.REQUEST:
            return self._render_request(message)
        else:
            return self._render_response(message)

    def _render_request(self, msg: HTTPMessage) -> str:
        parser = RequestParser()
        parsed = parser.parse(msg)

        lines = []
        lines.append("=" * 60)
        lines.append(f"Request #{msg.id} - Parsed View")
        lines.append("=" * 60)

        lines.append("\n[Request Line]")
        lines.append(f"  Method:    {parsed.method}")
        lines.append(f"  Host:      {parsed.host}")
        lines.append(f"  Path:      {parsed.path}")

        if parsed.query_params:
            lines.append(f"  Query:     {parsed.query_params}")

        lines.append("\n[Headers]")
        if parsed.headers:
            for k, v in parsed.headers.items():
                lines.append(f"  {k}: {v}")
        else:
            lines.append("  (none)")

        lines.append("\n[Cookies]")
        if parsed.cookies:
            for k, v in parsed.cookies.items():
                lines.append(f"  {k} = {v}")
        else:
            lines.append("  (none)")

        if parsed.body:
            lines.append(f"\n[Body] ({parsed.body_type}, {len(msg.body)} bytes)")
            lines.append("-" * 40)
            if parsed.body_type == 'json':
                try:
                    json_obj = json.loads(parsed.body)
                    lines.append(json.dumps(json_obj, indent=2))
                except:
                    lines.append(parsed.body)
            else:
                lines.append(parsed.body[:2000])
            lines.append("-" * 40)

        if parsed.form_params:
            lines.append("\n[Form Parameters]")
            for k, v in parsed.form_params.items():
                lines.append(f"  {k}: {v}")

        return "\n".join(lines)

    def _render_response(self, msg: HTTPMessage) -> str:
        parser = ResponseParser()
        parsed = parser.parse(msg)

        lines = []
        lines.append("=" * 60)
        lines.append("Response - Parsed View")
        lines.append("=" * 60)

        lines.append("\n[Status]")
        lines.append(f"  Code:     {parsed.status_code}")
        lines.append(f"  Text:     {parsed.status_text}")

        lines.append("\n[Headers]")
        if parsed.headers:
            for k, v in parsed.headers.items():
                lines.append(f"  {k}: {v}")
        else:
            lines.append("  (none)")

        lines.append("\n[Cookies]")
        if parsed.cookies:
            for k, v in parsed.cookies.items():
                lines.append(f"  {k} = {v}")
        else:
            lines.append("  (none)")

        lines.append(f"\n[Body] ({parsed.body_type}, {parsed.content_length} bytes)")
        lines.append("-" * 40)
        if parsed.body:
            if parsed.body_type == 'json':
                try:
                    json_obj = json.loads(parsed.body)
                    lines.append(json.dumps(json_obj, indent=2))
                except:
                    lines.append(parsed.body[:2000])
            else:
                lines.append(parsed.body[:2000])
        else:
            lines.append("(no body)")
        lines.append("-" * 40)

        return "\n".join(lines)


if __name__ == '__main__':
    from src.core.models import HTTPMessage, MessageType, Protocol

    req = HTTPMessage(
        id=1,
        type=MessageType.REQUEST,
        method="POST",
        url="http://example.com/api/login",
        host="example.com",
        path="/api/login?redirect=/dashboard",
        protocol=Protocol.HTTP,
        headers={
            "Content-Type": "application/json",
            "Cookie": "session=abc123; user=admin"
        },
        body=b'{"username": "admin", "password": "secret"}'
    )

    parsed_view = ParsedViewRenderer()
    print(parsed_view.render(req))