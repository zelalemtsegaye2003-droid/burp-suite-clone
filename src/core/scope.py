"""Scope Management for Target Tracking"""
import re
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse


@dataclass
class ScopeRule:
    pattern: str
    is_regex: bool = True
    enabled: bool = True


class ScopeManager:
    def __init__(self):
        self.include_rules: List[ScopeRule] = []
        self.exclude_rules: List[ScopeRule] = []
        self._include_cache: Dict[str, bool] = {}
        self._exclude_cache: Dict[str, bool] = {}

    def add_include(self, pattern: str):
        rule = ScopeRule(pattern=pattern, is_regex=True)
        self.include_rules.append(rule)
        self._clear_cache()

    def add_exclude(self, pattern: str):
        rule = ScopeRule(pattern=pattern, is_regex=True)
        self.exclude_rules.append(rule)
        self._clear_cache()

    def remove_include(self, index: int):
        if 0 <= index < len(self.include_rules):
            self.include_rules.pop(index)
            self._clear_cache()

    def remove_exclude(self, index: int):
        if 0 <= index < len(self.exclude_rules):
            self.exclude_rules.pop(index)
            self._clear_cache()

    def is_in_scope(self, url: str) -> bool:
        if url in self._include_cache:
            return self._include_cache[url]

        if not self.include_rules:
            result = True
        else:
            result = False
            for rule in self.include_rules:
                if rule.enabled:
                    try:
                        if rule.is_regex:
                            if re.search(rule.pattern, url, re.IGNORECASE):
                                result = True
                                break
                        else:
                            if rule.pattern.lower() in url.lower():
                                result = True
                                break
                    except:
                        pass

        self._include_cache[url] = result
        return result

    def is_excluded(self, url: str) -> bool:
        if url in self._exclude_cache:
            return self._exclude_cache[url]

        result = False
        for rule in self.exclude_rules:
            if rule.enabled:
                try:
                    if rule.is_regex:
                        if re.search(rule.pattern, url, re.IGNORECASE):
                            result = True
                            break
                    else:
                        if rule.pattern.lower() in url.lower():
                            result = True
                            break
                except:
                    pass

        self._exclude_cache[url] = result
        return result

    def should_process(self, url: str) -> bool:
        if self.is_excluded(url):
            return False
        return self.is_in_scope(url)

    def get_parsed_url(self, url: str) -> dict:
        try:
            parsed = urlparse(url)
            return {
                'scheme': parsed.scheme,
                'host': parsed.hostname or '',
                'port': parsed.port,
                'path': parsed.path,
                'params': parsed.query
            }
        except:
            return {}

    def get_domain(self, url: str) -> str:
        parsed = self.get_parsed_url(url)
        return parsed.get('host', '')

    def _clear_cache(self):
        self._include_cache.clear()
        self._exclude_cache.clear()

    def clear(self):
        self.include_rules.clear()
        self.exclude_rules.clear()
        self._clear_cache()

    def to_dict(self) -> Dict:
        return {
            'include': [r.pattern for r in self.include_rules],
            'exclude': [r.pattern for r in self.exclude_rules]
        }

    def from_dict(self, data: Dict):
        self.clear()
        for pattern in data.get('include', []):
            self.add_include(pattern)
        for pattern in data.get('exclude', []):
            self.add_exclude(pattern)


@dataclass
class SiteNode:
    url: str
    host: str
    path: str
    method: str = "GET"
    status_code: int = 0
    response_time: int = 0
    issues: int = 0
    children: List['SiteNode'] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    is_folder: bool = False


class SiteMap:
    def __init__(self):
        self.scope_manager = ScopeManager()
        self.nodes: Dict[str, SiteNode] = {}
        self.hosts: Dict[str, List[str]] = {}

    def add_url(self, url: str, method: str = "GET", status_code: int = 0, response_time: int = 0):
        if not self.scope_manager.should_process(url):
            return

        parsed = self.scope_manager.get_parsed_url(url)
        host = parsed.get('host', '')
        path = parsed.get('path', '/')

        if not host:
            return

        node = SiteNode(
            url=url,
            host=host,
            path=path,
            method=method,
            status_code=status_code,
            response_time=response_time
        )

        self.nodes[url] = node

        if host not in self.hosts:
            self.hosts[host] = []
        if url not in self.hosts[host]:
            self.hosts[host].append(url)

    def get_hosts(self) -> List[str]:
        return sorted(self.hosts.keys())

    def get_urls_for_host(self, host: str) -> List[str]:
        return sorted(self.hosts.get(host, []))

    def get_node(self, url: str) -> Optional[SiteNode]:
        return self.nodes.get(url)

    def get_summary(self) -> Dict:
        return {
            'total_urls': len(self.nodes),
            'hosts': len(self.hosts),
            'in_scope': sum(1 for url in self.nodes if self.scope_manager.is_in_scope(url)),
            'excluded': sum(1 for url in self.nodes if self.scope_manager.is_excluded(url))
        }

    def filter_by_status(self, status_codes: List[int]) -> List[SiteNode]:
        return [node for node in self.nodes.values() if node.status_code in status_codes]

    def filter_by_issues(self) -> List[SiteNode]:
        return [node for node in self.nodes.values() if node.issues > 0]

    def clear(self):
        self.nodes.clear()
        self.hosts.clear()


class TargetManager:
    def __init__(self):
        self.scope_manager = ScopeManager()
        self.sitemap = SiteMap()
        self.sitemap.scope_manager = self.scope_manager

    def add_target(self, url: str):
        self.scope_manager.add_include(url)

    def remove_target(self, index: int):
        self.scope_manager.remove_include(index)

    def add_exclusion(self, pattern: str):
        self.scope_manager.add_exclude(pattern)

    def is_in_scope(self, url: str) -> bool:
        return self.scope_manager.should_process(url)

    def add_to_sitemap(self, url: str, method: str = "GET", status_code: int = 0, response_time: int = 0):
        self.sitemap.add_url(url, method, status_code, response_time)

    def get_sitemap_summary(self) -> Dict:
        return self.sitemap.get_summary()

    def get_hosts(self) -> List[str]:
        return self.sitemap.get_hosts()

    def get_urls_for_host(self, host: str) -> List[str]:
        return self.sitemap.get_urls_for_host(host)


if __name__ == '__main__':
    tm = TargetManager()

    tm.add_target(".*example\\.com.*")
    tm.add_exclude(".*logout.*")

    test_urls = [
        "http://example.com/login",
        "http://example.com/admin",
        "http://example.com/logout",
        "http://other.com/test"
    ]

    for url in test_urls:
        print(f"{url}: in_scope={tm.is_in_scope(url)}")

    for url in test_urls:
        tm.add_to_sitemap(url, status_code=200)

    print(f"\nSitemap: {tm.get_sitemap_summary()}")