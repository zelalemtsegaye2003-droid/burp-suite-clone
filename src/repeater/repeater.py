"""Repeater - Manual Request Testing Tool"""
from typing import List, Dict, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import time
import requests
import socket
import ssl
from ..core.models import HTTPMessage, MessageType, Protocol


@dataclass
class RepeaterRequest:
    id: int
    name: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[bytes]
    timestamp: datetime = field(default_factory=datetime.now)
    response: Optional[bytes] = None
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_time_ms: int = 0
    notes: str = ""


class RepeaterHistory:
    def __init__(self, max_items: int = 100):
        self.max_items = max_items
        self.items: List[RepeaterRequest] = []
        self._next_id = 1

    def add(self, request: RepeaterRequest) -> int:
        if len(self.items) >= self.max_items:
            self.items.pop(0)

        request.id = self._next_id
        self._next_id += 1
        self.items.append(request)

        return request.id

    def get(self, request_id: int) -> Optional[RepeaterRequest]:
        for item in self.items:
            if item.id == request_id:
                return item
        return None

    def get_all(self) -> List[RepeaterRequest]:
        return self.items.copy()

    def delete(self, request_id: int) -> bool:
        for i, item in enumerate(self.items):
            if item.id == request_id:
                self.items.pop(i)
                return True
        return False

    def clear(self):
        self.items.clear()

    def search(self, keyword: str) -> List[RepeaterRequest]:
        results = []
        keyword_lower = keyword.lower()

        for item in self.items:
            if keyword_lower in item.url.lower() or keyword_lower in item.name.lower():
                results.append(item)

        return results


class Repeater:
    def __init__(self):
        self.history = RepeaterHistory()
        self.current_request: Optional[RepeaterRequest] = None
        self.session = requests.Session()
        self.session.verify = False

    def create_request(self, method: str, url: str, headers: Dict = None, body: bytes = None, name: str = "") -> RepeaterRequest:
        if not name:
            name = f"{method} {url[:50]}"

        request = RepeaterRequest(
            id=0,
            name=name,
            method=method,
            url=url,
            headers=headers or {},
            body=body
        )

        return request

    def send(self, request: RepeaterRequest) -> Tuple[bytes, int, Dict, int]:
        start_time = time.time()

        try:
            method = request.method.upper()
            url = request.url

            parsed_url = request.url
            if not parsed_url.startswith('http'):
                parsed_url = 'http://' + parsed_url

            response = self.session.request(
                method=method,
                url=parsed_url,
                headers=request.headers,
                data=request.body,
                timeout=30
            )

            response_time_ms = int((time.time() - start_time) * 1000)

            request.response = response.content
            request.response_status = response.status_code
            request.response_headers = dict(response.headers)
            request.response_time_ms = response_time_ms

            self.history.add(request)
            self.current_request = request

            return response.content, response.status_code, dict(response.headers), response_time_ms

        except Exception as e:
            response_time_ms = int((time.time() - start_time) * 1000)
            request.response = str(e).encode()
            request.response_status = 0
            request.response_time_ms = response_time_ms

            self.history.add(request)
            self.current_request = request

            return str(e).encode(), 0, {}, response_time_ms

    def update_request(self, request_id: int, method: str = None, url: str = None,
                      headers: Dict = None, body: bytes = None) -> bool:
        request = self.history.get(request_id)
        if not request:
            return False

        if method:
            request.method = method
        if url:
            request.url = url
        if headers:
            request.headers = headers
        if body is not None:
            request.body = body

        return True

    def get_history(self) -> List[RepeaterRequest]:
        return self.history.get_all()

    def get_request(self, request_id: int) -> Optional[RepeaterRequest]:
        return self.history.get(request_id)

    def delete_request(self, request_id: int) -> bool:
        return self.history.delete(request_id)

    def duplicate_request(self, request_id: int) -> Optional[RepeaterRequest]:
        original = self.history.get(request_id)
        if not original:
            return None

        duplicate = RepeaterRequest(
            id=0,
            name=f"{original.name} (copy)",
            method=original.method,
            url=original.url,
            headers=original.headers.copy(),
            body=original.body
        )

        self.history.add(duplicate)
        return duplicate


class ResponseComparator:
    def __init__(self):
        pass

    def compare(self, response1: bytes, response2: bytes) -> Dict:
        diff = {
            'length_diff': len(response2) - len(response1),
            'identical': response1 == response2,
            'differences': []
        }

        if response1 == response2:
            return diff

        try:
            text1 = response1.decode('utf-8', errors='ignore')
            text2 = response2.decode('utf-8', errors='ignore')

            lines1 = text1.split('\n')
            lines2 = text2.split('\n')

            max_lines = max(len(lines1), len(lines2))

            for i in range(max_lines):
                line1 = lines1[i] if i < len(lines1) else ""
                line2 = lines2[i] if i < len(lines2) else ""

                if line1 != line2:
                    diff['differences'].append({
                        'line': i + 1,
                        'old': line1[:100],
                        'new': line2[:100]
                    })

        except:
            diff['differences'].append('Binary content difference')

        return diff

    def compare_requests(self, req1_id: int, req2_id: int, repeater: Repeater) -> Dict:
        req1 = repeater.get_request(req1_id)
        req2 = repeater.get_request(req2_id)

        if not req1 or not req2:
            return {'error': 'Request not found'}

        if not req1.response or not req2.response:
            return {'error': 'No response available'}

        return self.compare(req1.response, req2.response)


class RepeaterTab:
    def __init__(self, name: str = "New Tab"):
        self.name = name
        self.request: Optional[RepeaterRequest] = None
        self.repeater = Repeater()

    def load_from_history(self, request_id: int):
        self.request = self.repeater.get_request(request_id)

    def send_request(self) -> Tuple[bytes, int, Dict, int]:
        if not self.request:
            return b"No request loaded", 0, {}, 0

        return self.repeater.send(self.request)

    def update_request(self, method: str = None, url: str = None,
                       headers: Dict = None, body: bytes = None):
        if not self.request:
            return

        if method:
            self.request.method = method
        if url:
            self.request.url = url
        if headers:
            self.request.headers = headers
        if body is not None:
            self.request.body = body


class RepeaterWorkspace:
    def __init__(self):
        self.tabs: List[RepeaterTab] = []
        self.active_tab: Optional[RepeaterTab] = None
        self._add_default_tab()

    def _add_default_tab(self):
        tab = RepeaterTab("Default")
        self.tabs.append(tab)
        self.active_tab = tab

    def add_tab(self, name: str = "New Tab") -> RepeaterTab:
        tab = RepeaterTab(name)
        self.tabs.append(tab)
        return tab

    def close_tab(self, tab: RepeaterTab) -> bool:
        if len(self.tabs) <= 1:
            return False

        if tab in self.tabs:
            self.tabs.remove(tab)

        if self.active_tab == tab:
            self.active_tab = self.tabs[0] if self.tabs else None

        return True

    def get_active_request(self) -> Optional[RepeaterRequest]:
        if self.active_tab and self.active_tab.request:
            return self.active_tab.request

        return None


def create_repeater_request(method: str, url: str) -> RepeaterRequest:
    repeater = Repeater()
    return repeater.create_request(method, url)


if __name__ == '__main__':
    repeater = Repeater()

    req = repeater.create_request("GET", "http://httpbin.org/get", name="Test Request")

    print(f"Sending: {req.method} {req.url}")

    response, status, headers, time_ms = repeater.send(req)

    print(f"Status: {status}, Time: {time_ms}ms")
    print(f"History: {len(repeater.history.items)} requests")

    history = repeater.get_history()
    for h in history:
        print(f"  #{h.id} {h.method} {h.url} -> {h.response_status}")