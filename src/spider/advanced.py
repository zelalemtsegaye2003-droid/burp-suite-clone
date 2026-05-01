"""Advanced Spider - Form detection, auto-fill, site map"""
from typing import List, Dict, Optional, Set, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlencode
from bs4 import BeautifulSoup
import json
import xml.etree.ElementTree as ET


@dataclass
class FormSubmission:
    url: str
    method: str
    form_data: Dict[str, str]
    inputs: List[Dict]


@dataclass
class SiteMapNode:
    url: str
    title: Optional[str] = None
    links: List[str] = field(default_factory=list)
    depth: int = 0
    status_code: int = 0
    children: List['SiteMapNode'] = field(default_factory=list)


class FormDetector:
    def __init__(self):
        pass

    def detect_forms(self, html: str, base_url: str) -> List[Dict]:
        forms = []

        try:
            soup = BeautifulSoup(html, 'html.parser')

            for form in soup.find_all('form'):
                form_info = self._parse_form(form, base_url)
                if form_info:
                    forms.append(form_info)

        except Exception as e:
            pass

        return forms

    def _parse_form(self, form, base_url: str) -> Optional[Dict]:
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()

        if not action:
            action = base_url

        if not action.startswith('http'):
            from urllib.parse import urljoin
            action = urljoin(base_url, action)

        inputs = []

        for inp in form.find_all(['input', 'select', 'textarea']):
            inp_type = inp.get('type', 'text').lower()
            name = inp.get('name', '')
            value = inp.get('value', '')
            required = inp.get('required') is not None

            if not name:
                continue

            inputs.append({
                'name': name,
                'type': inp_type,
                'value': value,
                'required': required
            })

        if not inputs:
            return None

        return {
            'action': action,
            'method': method,
            'inputs': inputs
        }

    def generate_payloads(self, form: Dict) -> List[Dict]:
        payloads = []

        default_payloads = {
            'username': ['admin', 'test', ''],
            'email': ['test@test.com', 'admin@test.com', ''],
            'password': ['admin', 'password', '123456', ''],
            'search': ['test', ''],
            'q': ['test', ''],
        }

        base_data = {}
        for inp in form['inputs']:
            name = inp['name']
            inp_type = inp['type']

            if inp_type in ['checkbox', 'radio']:
                if inp.get('value'):
                    base_data[name] = inp['value']
            else:
                default_value = default_payloads.get(name, [''])[0]
                base_data[name] = default_value

        payloads.append(base_data.copy())

        for name, default_vals in default_payloads.items():
            if name in base_data:
                for val in default_vals[1:]:
                    test_data = base_data.copy()
                    test_data[name] = val
                    if test_data not in payloads:
                        payloads.append(test_data)

        return payloads


class FormAutoFiller:
    def __init__(self):
        self.filled_forms: List[FormSubmission] = []

    def fill_form(self, form: Dict, fill_strategy: str = 'default') -> Dict[str, str]:
        form_data = {}

        for inp in form['inputs']:
            name = inp['name']
            inp_type = inp['type']
            value = inp.get('value', '')

            if inp_type in ['hidden', 'submit', 'button', 'image']:
                form_data[name] = value
                continue

            if inp_type == 'checkbox':
                form_data[name] = value or 'on'
                continue

            if fill_strategy == 'default':
                form_data[name] = self._default_value(name, inp_type)
            elif fill_strategy == 'test':
                form_data[name] = self._test_value(name, inp_type)
            elif fill_strategy == 'empty':
                form_data[name] = ''

        return form_data

    def _default_value(self, name: str, inp_type: str) -> str:
        name_lower = name.lower()

        if 'email' in name_lower:
            return 'test@example.com'
        elif 'name' in name_lower:
            return 'Test User'
        elif 'user' in name_lower:
            return 'admin'
        elif 'pass' in name_lower:
            return 'password123'
        elif 'phone' in name_lower:
            return '1234567890'
        elif 'age' in name_lower:
            return '25'
        elif 'url' in name_lower:
            return 'http://example.com'
        elif 'date' in name_lower:
            return '2024-01-01'
        elif 'number' in name_lower or inp_type == 'number':
            return '1'

        return 'test'

    def _test_value(self, name: str, inp_type: str) -> str:
        return f"test_{name}"

    def submit_form(self, form: Dict, form_data: Dict, session) -> Optional[Dict]:
        import requests

        url = form['action']
        method = form['method']

        try:
            if method == 'POST':
                response = session.post(url, data=form_data, timeout=30)
            else:
                response = session.get(url, params=form_data, timeout=30)

            return {
                'url': response.url,
                'status_code': response.status_code,
                'response_text': response.text[:1000],
                'success': 200 <= response.status_code < 300
            }
        except Exception as e:
            return {'error': str(e), 'success': False}


class SiteMapGenerator:
    def __init__(self):
        self.nodes: Dict[str, SiteMapNode] = {}
        self.root: Optional[SiteMapNode] = None

    def generate(self, crawl_results: List, start_url: str) -> SiteMapNode:
        self.nodes.clear()

        parsed = urlparse(start_url)
        self.root = SiteMapNode(url=start_url, depth=0)
        self.nodes[start_url] = self.root

        for result in crawl_results:
            if result.url not in self.nodes:
                self.nodes[result.url] = SiteMapNode(
                    url=result.url,
                    title=result.title,
                    status_code=result.status_code
                )

            parent = self.nodes[result.url]

            for link in result.links:
                if link not in self.nodes:
                    self.nodes[link] = SiteMapNode(url=link)

                child = self.nodes[link]
                parent.children.append(child)
                parent.links.append(link)

        return self.root

    def to_dict(self) -> Dict:
        return {url: {
            'title': node.title,
            'links': node.links,
            'status': node.status_code,
            'depth': node.depth
        } for url, node in self.nodes.items()}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_xml(self) -> str:
        root = ET.Element('urlset')
        root.set('xmlns', 'http://www.sitemaps.org/schemas/sitemap/0.9')

        for url, node in self.nodes.items():
            url_element = ET.SubElement(root, 'url')
            loc = ET.SubElement(url_element, 'loc')
            loc.text = node.url

            if node.title:
                title_elem = ET.SubElement(url_element, 'title')
                title_elem.text = node.title

            if node.status_code:
                status_elem = ET.SubElement(url_element, 'status')
                status_elem.text = str(node.status_code)

        return ET.tostring(root, encoding='unicode')

    def to_text(self, max_depth: int = 3) -> str:
        lines = []
        visited = set()

        def add_node(node: SiteMapNode, prefix: str = "", depth: int = 0):
            if depth > max_depth or node.url in visited:
                return

            visited.add(node.url)
            indent = "  " * depth
            title = f" - {node.title}" if node.title else ""
            status = f" [{node.status_code}]" if node.status_code else ""
            lines.append(f"{indent}* {node.url}{title}{status}")

            for child in node.children[:10]:
                add_node(child, prefix, depth + 1)

        if self.root:
            add_node(self.root)

        return "\n".join(lines)


class AdvancedSpider:
    def __init__(self, base_spider):
        self.spider = base_spider
        self.form_detector = FormDetector()
        self.form_filler = FormAutoFiller()
        self.sitemap_gen = SiteMapGenerator()

    def get_forms(self, html: str, base_url: str) -> List[Dict]:
        return self.form_detector.detect_forms(html, base_url)

    def generate_form_payloads(self, form: Dict) -> List[Dict]:
        return self.form_detector.generate_payloads(form)

    def fill_and_submit(self, form: Dict, strategy: str = 'default') -> Optional[Dict]:
        form_data = self.form_filler.fill_form(form, strategy)
        return self.form_filler.submit_form(form, form_data, self.spider.session)

    def generate_sitemap(self, results: List) -> SiteMapNode:
        return self.sitemap_gen.generate(results, self.spider.start_url)


if __name__ == '__main__':
    from crawler import Spider, CrawlConfig

    config = CrawlConfig(max_depth=1, max_pages=5)
    spider = Spider('http://example.com', config)
    results = spider.crawl()

    sitemap_gen = SiteMapGenerator()
    root = sitemap_gen.generate(results, 'http://example.com')

    print("Site Map:")
    print(sitemap_gen.to_text())