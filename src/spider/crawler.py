"""Web Spider/Crawler Module"""
from typing import List, Set, Optional, Dict, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, urlunparse
from collections import deque
import re
import requests
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('spider')


@dataclass
class CrawlResult:
    url: str
    status_code: int
    links: List[str]
    forms: List[Dict]
    title: Optional[str]
    resources: List[str]
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class CrawlConfig:
    max_depth: int = 3
    max_pages: int = 1000
    follow_external: bool = False
    follow_subdomains: bool = False
    obey_robots: bool = True
    user_agent: str = "BurpClone-Spider/1.0"
    timeout: int = 30
    concurrent_requests: int = 5


class URLExtractor:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.base_parsed = urlparse(base_url)

    def extract_links(self, html: str) -> List[str]:
        links = []

        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.findall(html):
            resolved = self._resolve_url(match)
            if resolved:
                links.append(resolved)

        links = list(set(links))
        return links

    def extract_forms(self, html: str) -> List[Dict]:
        forms = []

        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(1)

            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)

            form_data = {
                'action': self._resolve_url(action_match.group(1)) if action_match else '',
                'method': method_match.group(1).upper() if method_match else 'GET',
                'inputs': []
            }

            input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
            for inp in input_pattern.finditer(form_html):
                inp_str = inp.group(0)
                name_match = re.search(r'name=["\']([^"\']*)["\']', inp_str, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', inp_str, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', inp_str, re.IGNORECASE)

                if name_match:
                    form_data['inputs'].append({
                        'name': name_match.group(1),
                        'type': type_match.group(1) if type_match else 'text',
                        'value': value_match.group(1) if value_match else ''
                    })

            textarea_pattern = re.compile(r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>(.*?)</textarea>', re.IGNORECASE | re.DOTALL)
            for ta in textarea_pattern.finditer(form_html):
                form_data['inputs'].append({
                    'name': ta.group(1),
                    'type': 'textarea',
                    'value': ''
                })

            select_pattern = re.compile(r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>.*?</select>', re.IGNORECASE | re.DOTALL)
            for sel in select_pattern.finditer(form_html):
                form_data['inputs'].append({
                    'name': sel.group(1),
                    'type': 'select',
                    'value': ''
                })

            if form_data['inputs']:
                forms.append(form_data)

        return forms

    def extract_resources(self, html: str) -> List[str]:
        resources = []

        src_patterns = [
            (re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE), 'src'),
            (re.compile(r'href=["\']([^"\']+\.css[^"\']*)["\']', re.IGNORECASE), 'css'),
            (re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE), 'js'),
        ]

        for pattern, _ in src_patterns:
            for match in pattern.findall(html):
                resolved = self._resolve_url(match)
                if resolved:
                    resources.append(resolved)

        return list(set(resources))

    def extract_title(self, html: str) -> Optional[str]:
        title_match = re.search(r'<title[^>]*>([^<]*)</title>', html, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()
        return None

    def _resolve_url(self, url: str) -> Optional[str]:
        if not url:
            return None

        url = url.strip()

        if url.startswith(('javascript:', 'mailto:', 'tel:', 'data:', '#')):
            return None

        if url.startswith('/'):
            return urljoin(self.base_url, url)

        if not url.startswith('http'):
            return urljoin(self.base_url, url)

        try:
            parsed = urlparse(url)

            if parsed.fragment:
                url = url.split('#')[0]

            return url
        except:
            return None


class Spider:
    def __init__(self, start_url: str, config: CrawlConfig = None):
        self.start_url = start_url
        self.config = config or CrawlConfig()
        self.visited: Set[str] = set()
        self.queue = deque()
        self.results: List[CrawlResult] = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.config.user_agent})

        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc

        self.robots_checker = None
        if self.config.obey_robots:
            from .robots import RobotsChecker
            self.robots_checker = RobotsChecker(start_url)
            logger.info(f"Robots.txt loaded for {self.base_domain}")

        self.queue.append((start_url, 0))

    def crawl(self, progress_callback: Callable[[int, int, str], None] = None) -> List[CrawlResult]:
        logger.info(f"Starting crawl from {self.start_url}")

        while self.queue and len(self.visited) < self.config.max_pages:
            url, depth = self.queue.popleft()

            if url in self.visited:
                continue

            if depth > self.config.max_depth:
                continue

            if not self._should_crawl(url):
                logger.info(f"Skipping (out of scope): {url}")
                continue

            self.visited.add(url)

            if progress_callback:
                progress_callback(len(self.visited), len(self.queue), url)

            result = self._fetch_page(url)

            if result and not result.error:
                self.results.append(result)

                if depth < self.config.max_depth:
                    for link in result.links:
                        if link not in self.visited:
                            self.queue.append((link, depth + 1))

            logger.info(f"Crawled: {url} - {len(self.visited)} pages visited")

        logger.info(f"Crawl complete. Visited {len(self.visited)} pages")
        return self.results

    def _should_crawl(self, url: str) -> bool:
        parsed = urlparse(url)

        if parsed.netloc != self.base_domain:
            if self.config.follow_external:
                return self.config.follow_subdomains or parsed.netloc == self.base_domain
            return False

        if self.robots_checker:
            if not self.robots_checker.is_allowed(url, self.config.user_agent):
                logger.info(f"Skipping (robots.txt): {url}")
                return False

        return True

    def _fetch_page(self, url: str) -> Optional[CrawlResult]:
        try:
            response = self.session.get(url, timeout=self.config.timeout)

            if response.status_code != 200:
                return CrawlResult(
                    url=url,
                    status_code=response.status_code,
                    links=[], forms=[], title=None, resources=[],
                    error=f"HTTP {response.status_code}"
                )

            html = response.text

            extractor = URLExtractor(url)

            links = extractor.extract_links(html)
            forms = extractor.extract_forms(html)
            title = extractor.extract_title(html)
            resources = extractor.extract_resources(html)

            filtered_links = [l for l in links if self._should_crawl(l)]

            return CrawlResult(
                url=url,
                status_code=response.status_code,
                links=filtered_links,
                forms=forms,
                title=title,
                resources=resources
            )

        except requests.RequestException as e:
            logger.error(f"Error fetching {url}: {e}")
            return CrawlResult(
                url=url,
                status_code=0,
                links=[], forms=[], title=None, resources=[],
                error=str(e)
            )

    def get_sitemap(self) -> Dict:
        sitemap = {'pages': {}, 'forms': {}, 'resources': []}

        for result in self.results:
            sitemap['pages'][result.url] = {
                'title': result.title,
                'links': result.links,
                'status': result.status_code
            }

            for form in result.forms:
                if form['action'] not in sitemap['forms']:
                    sitemap['forms'][form['action']] = []
                sitemap['forms'][form['action']].append(form)

            sitemap['resources'].extend(result.resources)

        sitemap['resources'] = list(set(sitemap['resources']))

        return sitemap


class ConcurrentSpider(Spider):
    def __init__(self, start_url: str, config: CrawlConfig = None):
        super().__init__(start_url, config)
        self._lock = None

    def crawl(self, progress_callback: Callable = None) -> List[CrawlResult]:
        import threading
        self._lock = threading.Lock()

        return super().crawl(progress_callback)


if __name__ == '__main__':
    config = CrawlConfig(max_depth=2, max_pages=50, user_agent="TestSpider/1.0")
    spider = Spider("http://example.com", config)

    def progress(current, queue, url):
        print(f"Visited: {current}, Queue: {queue}, Current: {url}")

    results = spider.crawl(progress)
    print(f"\nCrawled {len(results)} pages")

    for r in results[:5]:
        print(f"  - {r.url} ({r.status_code}) - {r.title}")