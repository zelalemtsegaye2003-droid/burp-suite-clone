"""Spider Session & Authentication Handling"""
from typing import Dict, Optional, List, Callable
from dataclasses import dataclass, field
import threading
import time
import json
import os
import pickle
from ..spider.crawler import Spider, CrawlConfig


@dataclass
class SpiderSession:
    spider_state: Dict = field(default_factory=dict)
    visited_urls: List[str] = field(default_factory=list)
    queue_urls: List[str] = field(default_factory=list)
    crawl_stats: Dict = field(default_factory=lambda: {
        'pages_visited': 0,
        'pages_failed': 0,
        'start_time': None,
        'end_time': None
    })
    cookies: Dict = field(default_factory=dict)


class SessionManager:
    def __init__(self, session_file: str = "spider_session.pkl"):
        self.session_file = session_file
        self.current_session: Optional[SpiderSession] = None

    def create_session(self) -> SpiderSession:
        self.current_session = SpiderSession()
        self.current_session.crawl_stats['start_time'] = time.time()
        return self.current_session

    def save_session(self):
        if self.current_session and self.session_file:
            with open(self.session_file, 'wb') as f:
                pickle.dump(self.current_session, f)

    def load_session(self) -> Optional[SpiderSession]:
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, 'rb') as f:
                    self.current_session = pickle.load(f)
                    return self.current_session
            except:
                pass
        return None

    def clear_session(self):
        if os.path.exists(self.session_file):
            os.remove(self.session_file)
        self.current_session = None


class AuthHandler:
    def __init__(self):
        self.auth_methods = {
            'basic': self._basic_auth,
            'bearer': self._bearer_auth,
            'form': self._form_auth,
            'cookie': self._cookie_auth
        }

    def apply_auth(self, session, auth_config: Dict) -> bool:
        auth_type = auth_config.get('type', '').lower()

        if auth_type in self.auth_methods:
            return self.auth_methods[auth_type](session, auth_config)

        return False

    def _basic_auth(self, session, config: Dict) -> bool:
        import base64
        username = config.get('username', '')
        password = config.get('password', '')

        if not username:
            return False

        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode()

        session.headers['Authorization'] = f"Basic {encoded}"
        return True

    def _bearer_auth(self, session, config: Dict) -> bool:
        token = config.get('token', '')
        if not token:
            return False

        session.headers['Authorization'] = f"Bearer {token}"
        return True

    def _form_auth(self, session, config: Dict) -> bool:
        import requests

        login_url = config.get('login_url', '')
        username_field = config.get('username_field', 'username')
        password_field = config.get('password_field', 'password')
        username = config.get('username', '')
        password = config.get('password', '')

        if not login_url or not username:
            return False

        data = {
            username_field: username,
            password_field: password
        }

        extra_fields = config.get('extra_fields', {})
        data.update(extra_fields)

        try:
            response = session.post(login_url, data=data, allow_redirects=True)

            if response.status_code == 200:
                session.authenticated = True
                return True
        except:
            pass

        return False

    def _cookie_auth(self, session, config: Dict) -> bool:
        cookies = config.get('cookies', {})
        if not cookies:
            return False

        for name, value in cookies.items():
            session.cookies.set(name, value)

        return True


class SpiderWithSession(Spider):
    def __init__(self, start_url: str, config: CrawlConfig = None):
        super().__init__(start_url, config)
        self.session_manager = SessionManager()
        self.auth_handler = AuthHandler()
        self.paused = False
        self._pause_lock = threading.Lock()
        self._save_interval = 50

    def crawl(self, progress_callback: Callable = None) -> List:
        session = self.session_manager.create_session()

        loaded_session = self.session_manager.load_session()
        if loaded_session:
            self.visited = set(loaded_session.visited_urls)
            for url in loaded_session.queue_urls:
                if url not in self.visited:
                    self.queue.append((url, 0))

            session.crawl_stats['pages_visited'] = len(self.visited)
            print(f"Resumed session: {len(self.visited)} pages already visited")

        page_count = 0

        while self.queue and len(self.visited) < self.config.max_pages:
            with self._pause_lock:
                if self.paused:
                    self._save_state(session)
                    while self.paused:
                        time.sleep(0.5)

            if not self._should_crawl_url():
                break

            url, depth = self.queue.popleft()

            if url in self.visited:
                continue

            if depth > self.config.max_depth:
                continue

            self.visited.add(url)

            if progress_callback:
                progress_callback(len(self.visited), len(self.queue), url)

            result = self._fetch_page(url)

            if result and not result.error:
                self.results.append(result)
                session.crawl_stats['pages_visited'] += 1

                if depth < self.config.max_depth:
                    for link in result.links:
                        if link not in self.visited:
                            self.queue.append((link, depth + 1))

            else:
                session.crawl_stats['pages_failed'] += 1

            page_count += 1
            if page_count % self._save_interval == 0:
                self._save_state(session)

        session.crawl_stats['end_time'] = time.time()
        self.session_manager.save_session()

        return self.results

    def _should_crawl_url(self) -> bool:
        with self._pause_lock:
            return not self.paused

    def _save_state(self, session: SpiderSession):
        session.visited_urls = list(self.visited)
        session.queue_urls = [url for url, _ in self.queue]
        session.cookies = dict(self.session.cookies)
        self.session_manager.save_session()

    def pause(self):
        with self._pause_lock:
            self.paused = True
            print("[*] Spider paused")

    def resume(self):
        with self._pause_lock:
            self.paused = False
            print("[*] Spider resumed")

    def apply_auth(self, auth_config: Dict) -> bool:
        return self.auth_handler.apply_auth(self.session, auth_config)

    def save_state(self, filename: str = "spider_state.json"):
        state = {
            'visited': list(self.visited),
            'queue': [(url, depth) for url, depth in self.queue],
            'results_count': len(self.results),
            'config': {
                'max_depth': self.config.max_depth,
                'max_pages': self.config.max_pages,
                'user_agent': self.config.user_agent
            }
        }

        with open(filename, 'w') as f:
            json.dump(state, f, indent=2)

        print(f"[*] State saved to {filename}")

    def load_state(self, filename: str = "spider_state.json"):
        if not os.path.exists(filename):
            return False

        with open(filename, 'r') as f:
            state = json.load(f)

        self.visited = set(state.get('visited', []))
        self.queue = [(url, depth) for url, depth in state.get('queue', [])]

        if 'config' in state:
            cfg = state['config']
            if 'max_depth' in cfg:
                self.config.max_depth = cfg['max_depth']
            if 'max_pages' in cfg:
                self.config.max_pages = cfg['max_pages']

        print(f"[*] State loaded from {filename}")
        print(f"    Visited: {len(self.visited)}, Queue: {len(self.queue)}")

        return True


if __name__ == '__main__':
    from crawler import CrawlConfig

    config = CrawlConfig(max_depth=2, max_pages=20)
    spider = SpiderWithSession('http://example.com', config)

    spider.apply_auth({
        'type': 'bearer',
        'token': 'test-token-123'
    })

    print("Spider with session support initialized")

    def progress(current, queue, url):
        print(f"Progress: {current} visited, {queue} queued")

    results = spider.crawl(progress)
    print(f"\nCrawled {len(results)} pages")