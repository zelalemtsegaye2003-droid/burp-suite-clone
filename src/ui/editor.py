"""In-place Request/Response Editor"""
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from ..core.models import HTTPMessage, MessageType, Protocol
from urllib.parse import urlparse, urlunparse
import json


@dataclass
class EditResult:
    success: bool
    message: str
    modified_message: Optional[HTTPMessage] = None


class RequestEditor:
    def __init__(self):
        pass

    def edit(self, message: HTTPMessage, changes: Dict) -> EditResult:
        try:
            if 'method' in changes:
                message.method = changes['method']

            if 'url' in changes:
                message.url = changes['url']
                parsed = urlparse(changes['url'])
                message.host = parsed.hostname or message.host
                message.path = parsed.path or '/'
                if parsed.query:
                    message.path += '?' + parsed.query
                message.protocol = Protocol.HTTPS if parsed.scheme == 'https' else Protocol.HTTP

            if 'path' in changes:
                message.path = changes['path']

            if 'headers' in changes:
                message.headers.update(changes['headers'])

            if 'remove_headers' in changes:
                for header in changes['remove_headers']:
                    message.headers.pop(header, None)

            if 'body' in changes:
                body = changes['body']
                if isinstance(body, str):
                    message.body = body.encode('utf-8')
                elif isinstance(body, bytes):
                    message.body = body
                elif body is None:
                    message.body = None

            if 'query_params' in changes:
                message.path = self._update_query_params(message.path, changes['query_params'])

            return EditResult(True, "Request modified successfully", message)

        except Exception as e:
            return EditResult(False, f"Edit failed: {str(e)}")

    def _update_query_params(self, path: str, params: Dict) -> str:
        parsed = urlparse(path)
        query_dict = {}

        if parsed.query:
            for pair in parsed.query.split('&'):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    query_dict[k] = v

        query_dict.update(params)

        new_query = '&'.join(f"{k}={v}" for k, v in query_dict.items())
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def add_header(self, message: HTTPMessage, name: str, value: str) -> EditResult:
        message.headers[name] = value
        return EditResult(True, f"Header '{name}' added", message)

    def remove_header(self, message: HTTPMessage, name: str) -> EditResult:
        if name in message.headers:
            del message.headers[name]
            return EditResult(True, f"Header '{name}' removed", message)
        return EditResult(False, f"Header '{name}' not found")

    def modify_body(self, message: HTTPMessage, new_body: str) -> EditResult:
        try:
            message.body = new_body.encode('utf-8')
            return EditResult(True, "Body modified", message)
        except Exception as e:
            return EditResult(False, f"Body modification failed: {e}")

    def change_method(self, message: HTTPMessage, new_method: str) -> EditResult:
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']
        if new_method.upper() not in valid_methods:
            return EditResult(False, f"Invalid method: {new_method}")

        message.method = new_method.upper()
        return EditResult(True, f"Method changed to {message.method}", message)

    def change_url(self, message: HTTPMessage, new_url: str) -> EditResult:
        try:
            parsed = urlparse(new_url)
            if not parsed.scheme:
                return EditResult(False, "Invalid URL - missing scheme")

            message.url = new_url
            message.host = parsed.hostname
            message.path = parsed.path or '/'
            if parsed.query:
                message.path += '?' + parsed.query
            message.protocol = Protocol.HTTPS if parsed.scheme == 'https' else Protocol.HTTP

            return EditResult(True, f"URL changed to {new_url}", message)
        except Exception as e:
            return EditResult(False, f"URL modification failed: {e}")


class ResponseEditor:
    def __init__(self):
        pass

    def edit(self, message: HTTPMessage, changes: Dict) -> EditResult:
        try:
            if 'status_code' in changes:
                message.status_code = changes['status_code']

            if 'status_text' in changes:
                message.status_text = changes['status_text']

            if 'headers' in changes:
                message.headers.update(changes['headers'])

            if 'remove_headers' in changes:
                for header in changes['remove_headers']:
                    message.headers.pop(header, None)

            if 'body' in changes:
                body = changes['body']
                if isinstance(body, str):
                    message.body = body.encode('utf-8')
                elif isinstance(body, bytes):
                    message.body = body

            if 'add_header' in changes:
                for name, value in changes['add_header'].items():
                    message.headers[name] = value

            return EditResult(True, "Response modified successfully", message)

        except Exception as e:
            return EditResult(False, f"Edit failed: {str(e)}")

    def change_status(self, message: HTTPMessage, code: int, text: str = None) -> EditResult:
        if not (100 <= code < 600):
            return EditResult(False, f"Invalid status code: {code}")

        message.status_code = code

        if text:
            message.status_text = text
        else:
            message.status_text = self._get_default_status_text(code)

        return EditResult(True, f"Status changed to {code}", message)

    def inject_body(self, message: HTTPMessage, injection: str, position: str = 'prepend') -> EditResult:
        if not message.body:
            message.body = injection.encode()
            return EditResult(True, f"Body set to injected content", message)

        try:
            original = message.body.decode('utf-8')
        except:
            return EditResult(False, "Cannot decode body for injection")

        if position == 'prepend':
            new_body = injection + original
        elif position == 'append':
            new_body = original + injection
        else:
            return EditResult(False, f"Invalid position: {position}")

        message.body = new_body.encode('utf-8')
        return EditResult(True, f"Body injected at {position}", message)

    def _get_default_status_text(self, code: int) -> str:
        texts = {
            200: "OK", 201: "Created", 204: "No Content",
            301: "Moved Permanently", 302: "Found", 304: "Not Modified",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
            404: "Not Found", 405: "Method Not Allowed",
            500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable"
        }
        return texts.get(code, "Unknown")


class MessageEditor:
    def __init__(self):
        self.request_editor = RequestEditor()
        self.response_editor = ResponseEditor()

    def edit(self, message: HTTPMessage, changes: Dict) -> EditResult:
        if message.type == MessageType.REQUEST:
            return self.request_editor.edit(message, changes)
        else:
            return self.response_editor.edit(message, changes)

    def edit_request(self, message: HTTPMessage, changes: Dict) -> EditResult:
        return self.request_editor.edit(message, changes)

    def edit_response(self, message: HTTPMessage, changes: Dict) -> EditResult:
        return self.response_editor.edit(message, changes)

    def validate(self, message: HTTPMessage) -> Tuple[bool, List[str]]:
        errors = []

        if message.type == MessageType.REQUEST:
            if not message.method:
                errors.append("Missing method")
            if not message.host:
                errors.append("Missing host")

        if message.type == MessageType.RESPONSE:
            if not message.status_code:
                errors.append("Missing status code")

        return len(errors) == 0, errors


class BatchEditor:
    def __init__(self, editor: MessageEditor):
        self.editor = editor
        self.history: List[Tuple[HTTPMessage, Dict]] = []

    def apply_changes(self, messages: List[HTTPMessage], changes: Dict) -> List[EditResult]:
        results = []
        for msg in messages:
            result = self.editor.edit(msg, changes)
            results.append(result)
            if result.success:
                self.history.append((msg, changes))
        return results

    def undo_last(self) -> bool:
        if not self.history:
            return False

        last_msg, last_changes = self.history.pop()
        reverse_changes = self._reverse_changes(last_changes)

        result = self.editor.edit(last_msg, reverse_changes)
        return result.success

    def _reverse_changes(self, changes: Dict) -> Dict:
        reverse = {}
        if 'body' in changes:
            reverse['body'] = b''
        return reverse


if __name__ == '__main__':
    from src.core.models import HTTPMessage, MessageType, Protocol

    req = HTTPMessage(
        id=1,
        type=MessageType.REQUEST,
        method="GET",
        url="http://example.com/api",
        host="example.com",
        path="/api",
        protocol=Protocol.HTTP,
        headers={"User-Agent": "Test"}
    )

    editor = MessageEditor()

    result = editor.edit_request(req, {'method': 'POST', 'headers': {'Content-Type': 'application/json'}})
    print(f"Edit result: {result.success} - {result.message}")
    print(f"New method: {req.method}")
    print(f"New headers: {req.headers}")