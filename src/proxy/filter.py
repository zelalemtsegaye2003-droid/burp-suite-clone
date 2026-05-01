"""Request/Response Filtering Module"""
import re
from typing import List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


class FilterAction(Enum):
    ALLOW = "allow"
    DENY = "deny"


class FilterType(Enum):
    DOMAIN = "domain"
    URL = "url"
    METHOD = "method"
    STATUS_CODE = "status_code"
    CONTENT_TYPE = "content_type"
    REGEX = "regex"


@dataclass
class FilterRule:
    type: FilterType
    pattern: str
    action: FilterAction
    enabled: bool = True
    description: str = ""

    def matches(self, method: str = None, url: str = None,
                domain: str = None, status_code: int = None,
                content_type: str = None, body: bytes = None) -> bool:
        try:
            if self.type == FilterType.DOMAIN and domain:
                return bool(re.search(self.pattern, domain, re.IGNORECASE))

            elif self.type == FilterType.URL and url:
                return bool(re.search(self.pattern, url, re.IGNORECASE))

            elif self.type == FilterType.METHOD and method:
                return bool(re.match(self.pattern, method, re.IGNORECASE))

            elif self.type == FilterType.STATUS_CODE and status_code:
                if '-' in self.pattern:
                    start, end = self.pattern.split('-')
                    return start <= str(status_code) <= end
                return str(status_code) == self.pattern

            elif self.type == FilterType.CONTENT_TYPE and content_type:
                return bool(re.search(self.pattern, content_type, re.IGNORECASE))

            elif self.type == FilterType.REGEX:
                search_in = url or ""
                if body:
                    try:
                        search_in += body.decode('utf-8', errors='ignore')
                    except:
                        pass
                return bool(re.search(self.pattern, search_in, re.IGNORECASE))

        except re.error:
            return False

        return False


@dataclass
class RequestFilter:
    rules: List[FilterRule] = field(default_factory=list)
    default_action: FilterAction = FilterAction.ALLOW
    blacklist_mode: bool = True

    def add_rule(self, rule: FilterRule):
        self.rules.append(rule)

    def should_allow(self, method: str = None, url: str = None,
                     domain: str = None, status_code: int = None,
                     content_type: str = None, body: bytes = None) -> bool:
        for rule in self.rules:
            if not rule.enabled:
                continue

            if rule.matches(method, url, domain, status_code, content_type, body):
                return rule.action == FilterAction.ALLOW

        return self.default_action == FilterAction.ALLOW if not self.blacklist_mode else True


class FilterManager:
    def __init__(self):
        self.url_blacklist: Set[str] = set()
        self.url_whitelist: Set[str] = set()
        self.domain_blacklist: Set[str] = set()
        self.domain_whitelist: Set[str] = set()
        self.method_blacklist: Set[str] = set()
        self.status_code_blacklist: Set[int] = set()
        self.request_filter = RequestFilter()
        self.response_filter = RequestFilter()

    def add_blacklist_url(self, pattern: str):
        self.url_blacklist.add(pattern)
        self.request_filter.add_rule(FilterRule(
            type=FilterType.URL,
            pattern=pattern,
            action=FilterAction.DENY,
            description="Blacklisted URL"
        ))

    def add_whitelist_url(self, pattern: str):
        self.url_whitelist.add(pattern)
        self.request_filter.add_rule(FilterRule(
            type=FilterType.URL,
            pattern=pattern,
            action=FilterAction.ALLOW,
            description="Whitelisted URL"
        ))

    def add_blacklist_domain(self, domain: str):
        self.domain_blacklist.add(domain.lower())
        self.request_filter.add_rule(FilterRule(
            type=FilterType.DOMAIN,
            pattern=domain,
            action=FilterAction.DENY,
            description="Blacklisted domain"
        ))

    def add_whitelist_domain(self, domain: str):
        self.domain_whitelist.add(domain.lower())
        self.request_filter.add_rule(FilterRule(
            type=FilterType.DOMAIN,
            pattern=domain,
            action=FilterAction.ALLOW,
            description="Whitelisted domain"
        ))

    def add_blacklist_method(self, method: str):
        self.method_blacklist.add(method.upper())
        self.request_filter.add_rule(FilterRule(
            type=FilterType.METHOD,
            pattern=method,
            action=FilterAction.DENY,
            description=f"Blacklisted method: {method}"
        ))

    def add_blacklist_status(self, code: int):
        self.status_code_blacklist.add(code)
        self.response_filter.add_rule(FilterRule(
            type=FilterType.STATUS_CODE,
            pattern=str(code),
            action=FilterAction.DENY,
            description=f"Blacklisted status code: {code}"
        ))

    def block_response_status(self, codes: List[int]):
        for code in codes:
            self.add_blacklist_status(code)

    def should_allow_request(self, method: str, url: str, domain: str) -> tuple[bool, str]:
        if self.method_blacklist and method.upper() in self.method_blacklist:
            return False, f"Method {method} is blacklisted"

        if self.domain_blacklist:
            for blocked in self.domain_blacklist:
                if blocked in domain.lower():
                    return False, f"Domain {domain} is blacklisted"

        if self.url_blacklist:
            for blocked in self.url_blacklist:
                if blocked.lower() in url.lower():
                    return False, f"URL {url} matches blacklist"

        if not self.request_filter.should_allow(method=method, url=url, domain=domain):
            return False, "Request filtered by rules"

        return True, ""

    def should_allow_response(self, status_code: int, content_type: str = None) -> tuple[bool, str]:
        if self.status_code_blacklist and status_code in self.status_code_blacklist:
            return False, f"Status code {status_code} is blacklisted"

        if not self.response_filter.should_allow(status_code=status_code, content_type=content_type):
            return False, "Response filtered by rules"

        return True, ""

    def clear_blacklist(self):
        self.url_blacklist.clear()
        self.domain_blacklist.clear()
        self.method_blacklist.clear()
        self.status_code_blacklist.clear()
        self.request_filter.rules.clear()
        self.response_filter.rules.clear()

    def clear_whitelist(self):
        self.url_whitelist.clear()
        self.domain_whitelist.clear()


if __name__ == '__main__':
    fm = FilterManager()

    fm.add_blacklist_domain("ads")
    fm.add_blacklist_domain("tracker")
    fm.add_blacklist_method("TRACE")
    fm.add_blacklist_status(404)

    allow, reason = fm.should_allow_request("GET", "http://example.com", "example.com")
    print(f"GET example.com: {allow}")

    allow, reason = fm.should_allow_request("TRACE", "http://test.com", "test.com")
    print(f"TRACE test.com: {allow} - {reason}")

    allow, reason = fm.should_allow_response(404)
    print(f"Response 404: {allow}")

    fm.add_blacklist_url("secret")
    allow, reason = fm.should_allow_request("GET", "http://example.com/secret", "example.com")
    print(f"GET /secret: {allow} - {reason}")