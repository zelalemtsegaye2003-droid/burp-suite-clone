"""Traffic History Viewer UI"""
from typing import List, Optional, Callable, Dict
from dataclasses import dataclass
from datetime import datetime
import threading
from ..proxy.database import ProxyDatabase
from ..core.models import HTTPMessage, MessageType, Protocol, FilterState


@dataclass
class HistoryViewItem:
    id: int
    method: str
    url: str
    status: Optional[int]
    host: str
    path: str
    length: int
    mime_type: str
    timestamp: str
    response_time_ms: int


class HistoryViewer:
    def __init__(self, db_path: str = "proxy_history.db"):
        self.db = ProxyDatabase(db_path)
        self.filter = FilterState()
        self._lock = threading.Lock()
        self._items: List[HistoryViewItem] = []
        self._callbacks: List[Callable] = []
        self._load_items()

    def _load_items(self):
        requests = self.db.get_requests(limit=1000)
        self._items = []
        for req in requests:
            status = None
            mime_type = ""
            length = 0

            detail = self.db.get_request_detail(req['id'])
            if detail and 'response' in detail:
                status = detail['response']['status_code']
                resp_headers = detail['response'].get('headers', {})
                mime_type = resp_headers.get('Content-Type', '')
                body = detail['response'].get('body')
                if body:
                    length = len(body)

            self._items.append(HistoryViewItem(
                id=req['id'],
                method=req['method'],
                url=req['url'],
                status=status,
                host=req.get('host', ''),
                path=req.get('path', '/'),
                length=length,
                mime_type=mime_type,
                timestamp=req['timestamp'],
                response_time_ms=0
            ))

    def refresh(self):
        with self._lock:
            self._load_items()
            self._notify()

    def get_items(self, offset: int = 0, limit: int = 100) -> List[HistoryViewItem]:
        with self._lock:
            filtered = self._apply_filter()
            return filtered[offset:offset + limit]

    def _apply_filter(self) -> List[HistoryViewItem]:
        if not self.filter.search_text:
            return self._items

        results = []
        search = self.filter.search_text.lower()

        for item in self._items:
            if search in item.url.lower() or search in item.host.lower():
                if self.filter.show_only_methods:
                    if item.method not in self.filter.show_only_methods:
                        continue
                if self.filter.show_only_status:
                    if item.status not in self.filter.show_only_status:
                        continue
                results.append(item)

        return results

    def get_item_detail(self, item_id: int) -> Optional[Dict]:
        return self.db.get_request_detail(item_id)

    def set_filter(self, filter_state: FilterState):
        self.filter = filter_state
        self._notify()

    def search(self, keyword: str) -> List[HistoryViewItem]:
        results = self.db.search_requests(keyword)
        items = []
        for req in results:
            items.append(HistoryViewItem(
                id=req['id'],
                method=req['method'],
                url=req['url'],
                status=None,
                host=req.get('host', ''),
                path=req.get('path', '/'),
                length=0,
                mime_type="",
                timestamp=req['timestamp'],
                response_time_ms=0
            ))
        return items

    def delete_item(self, item_id: int):
        self.db.delete_request(item_id)
        self._load_items()
        self._notify()

    def clear_all(self):
        self.db.clear_all()
        self._items = []
        self._notify()

    def on_update(self, callback: Callable):
        self._callbacks.append(callback)

    def _notify(self):
        for cb in self._callbacks:
            try:
                cb(self._items)
            except:
                pass


class HistoryTableDisplay:
    @staticmethod
    def format_table(items: List[HistoryViewItem], show_detail: bool = False) -> str:
        if not items:
            return "No requests to display."

        header = f"{'#':<4} {'Method':<8} {'Status':<8} {'Host':<25} {'Path':<30} {'Length':<10} {'MIME':<20}"
        separator = "-" * 120

        lines = [header, separator]

        for i, item in enumerate(items):
            status_str = str(item.status) if item.status else "-"
            path = item.path[:28] + ".." if len(item.path) > 30 else item.path
            mime = item.mime_type[:18] if item.mime_type else "-"

            lines.append(f"{i+1:<4} {item.method:<8} {status_str:<8} {item.host[:25]:<25} {path:<30} {item.length:<10} {mime:<20}")

        return "\n".join(lines)

    @staticmethod
    def format_detail(detail: Dict) -> str:
        if not detail:
            return "No details available."

        lines = []
        lines.append("=" * 60)
        lines.append(f"Request #{detail.get('id')}")
        lines.append("=" * 60)

        req = detail
        lines.append(f"\n--- REQUEST ---")
        lines.append(f"Method: {req.get('method')}")
        lines.append(f"URL: {req.get('url')}")
        lines.append(f"Host: {req.get('host')}")
        lines.append(f"Path: {req.get('path')}")
        lines.append(f"Timestamp: {req.get('timestamp')}")

        headers = req.get('headers', {})
        if headers:
            lines.append("\nHeaders:")
            for k, v in headers.items():
                lines.append(f"  {k}: {v}")

        body = req.get('body')
        if body:
            try:
                body_text = body.decode('utf-8', errors='replace')
                lines.append(f"\nBody ({len(body)} bytes):")
                lines.append(body_text[:2000])
            except:
                lines.append(f"\nBody: {body.hex()[:100]}")

        if 'response' in detail:
            lines.append(f"\n--- RESPONSE ---")
            resp = detail['response']
            lines.append(f"Status: {resp.get('status_code')} {resp.get('status_text')}")
            lines.append(f"Timestamp: {resp.get('timestamp')}")

            resp_headers = resp.get('headers', {})
            if resp_headers:
                lines.append("\nHeaders:")
                for k, v in resp_headers.items():
                    lines.append(f"  {k}: {v}")

            resp_body = resp.get('body')
            if resp_body:
                try:
                    body_text = resp_body.decode('utf-8', errors='replace')
                    lines.append(f"\nBody ({len(resp_body)} bytes):")
                    lines.append(body_text[:2000])
                except:
                    lines.append(f"\nBody: {resp_body.hex()[:100]}")

        return "\n".join(lines)


if __name__ == '__main__':
    viewer = HistoryViewer()
    items = viewer.get_items(limit=10)
    print(HistoryTableDisplay.format_table(items))