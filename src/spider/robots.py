"""Robots.txt Parser"""
from typing import List, Set, Dict, Optional
from dataclasses import dataclass
from urllib.parse import urlparse
import re
import requests
import logging

logger = logging.getLogger('robots')


@dataclass
class RobotRule:
    user_agent: str
    disallow: List[str]
    allow: List[str]
    crawl_delay: Optional[float] = None


class RobotsTxtParser:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.base_parsed = urlparse(base_url)
        self.rules: Dict[str, RobotRule] = {}
        self.sitemaps: List[str] = []
        self._fetch_robots()

    def _fetch_robots(self):
        robots_url = f"{self.base_parsed.scheme}://{self.base_parsed.netloc}/robots.txt"

        try:
            response = requests.get(robots_url, timeout=10, headers={'User-Agent': 'BurpClone-Spider'})
            if response.status_code == 200:
                self._parse(response.text)
                logger.info(f"Loaded robots.txt from {robots_url}")
            else:
                logger.info(f"No robots.txt found at {robots_url}")
        except Exception as e:
            logger.error(f"Error fetching robots.txt: {e}")

    def _parse(self, content: str):
        current_user_agent = '*'
        current_disallow = []
        current_allow = []
        crawl_delay = None

        for line in content.split('\n'):
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            if ':' not in line:
                continue

            key, value = line.split(':', 1)
            key = key.strip().lower()
            value = value.strip()

            if key == 'user-agent':
                if current_user_agent != '*' and current_disallow:
                    self.rules[current_user_agent] = RobotRule(
                        current_user_agent, current_disallow.copy(), current_allow.copy(), crawl_delay
                    )

                current_user_agent = value
                current_disallow = []
                current_allow = []
                crawl_delay = None

            elif key == 'disallow':
                if value:
                    current_disallow.append(value)

            elif key == 'allow':
                if value:
                    current_allow.append(value)

            elif key == 'crawl-delay':
                try:
                    crawl_delay = float(value)
                except:
                    pass

            elif key == 'sitemap':
                self.sitemaps.append(value)

        if current_user_agent and current_disallow:
            self.rules[current_user_agent] = RobotRule(
                current_user_agent, current_disallow, current_allow, crawl_delay
            )

    def can_fetch(self, url: str, user_agent: str = 'BurpClone-Spider') -> bool:
        parsed = urlparse(url)
        path = parsed.path or '/'

        if parsed.query:
            path += '?' + parsed.query

        rules_to_check = []

        if user_agent in self.rules:
            rules_to_check.append(self.rules[user_agent])

        if '*' in self.rules:
            rules_to_check.append(self.rules['*'])

        if not rules_to_check:
            return True

        for rule in rules_to_check:
            if rule.crawl_delay:
                pass

            for allow_path in rule.allow:
                if self._match_path(path, allow_path):
                    return True

            for disallow_path in rule.disallow:
                if self._match_path(path, disallow_path):
                    return False

        return True

    def _match_path(self, path: str, pattern: str) -> bool:
        if not pattern:
            return False

        if pattern == '/':
            return True

        if pattern.endswith('$'):
            pattern = pattern[:-1]
            return path == pattern

        if '*' in pattern:
            regex_pattern = pattern.replace('*', '.*')
            regex_pattern = '^' + regex_pattern
            return bool(re.match(regex_pattern, path))

        return path.startswith(pattern)

    def get_crawl_delay(self, user_agent: str = 'BurpClone-Spider') -> Optional[float]:
        if user_agent in self.rules and self.rules[user_agent].crawl_delay:
            return self.rules[user_agent].crawl_delay

        if '*' in self.rules:
            return self.rules['*'].crawl_delay

        return None

    def get_sitemaps(self) -> List[str]:
        return self.sitemaps

    def get_disallowed_paths(self, user_agent: str = 'BurpClone-Spider') -> List[str]:
        if user_agent in self.rules:
            return self.rules[user_agent].disallow

        if '*' in self.rules:
            return self.rules['*'].disallow

        return []


class RobotsChecker:
    def __init__(self, base_url: str):
        self.parser = RobotsTxtParser(base_url)

    def is_allowed(self, url: str, user_agent: str = 'BurpClone-Spider') -> bool:
        return self.parser.can_fetch(url, user_agent)

    def get_delay(self, user_agent: str = 'BurpClone-Spider') -> Optional[float]:
        return self.parser.get_crawl_delay(user_agent)

    def get_sitemaps(self) -> List[str]:
        return self.parser.get_sitemaps()

    def filter_allowed_urls(self, urls: List[str], user_agent: str = 'BurpClone-Spider') -> List[str]:
        allowed = []
        for url in urls:
            if self.is_allowed(url, user_agent):
                allowed.append(url)
        return allowed


if __name__ == '__main__':
    checker = RobotsChecker('http://example.com')

    print(f"Allowed /: {checker.is_allowed('http://example.com/')}")
    print(f"Allowed /admin: {checker.is_allowed('http://example.com/admin')}")
    print(f"Sitemaps: {checker.get_sitemaps()}")
    print(f"Crawl delay: {checker.get_delay()}")