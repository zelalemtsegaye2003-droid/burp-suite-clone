"""Proxy Module"""
from .server import ProxyServer
from .https_proxy import HTTPSProxy
from .database import ProxyDatabase
from .ssl_cert import SSLCertGenerator
from .filter import FilterManager, FilterRule, FilterAction, FilterType
from .chaining import ProxyChain, ProxyChainer
from .interceptor import RequestInterceptor, InterceptState

# Optional passive scanner - import from scanner module
try:
    from ..scanner.passive import PassiveScanner
except ImportError:
    PassiveScanner = None

__all__ = ['ProxyServer', 'HTTPSProxy', 'ProxyDatabase', 'SSLCertGenerator', 'FilterManager', 'FilterRule', 'FilterAction', 'FilterType', 'ProxyChain', 'ProxyChainer', 'RequestInterceptor', 'InterceptState', 'PassiveScanner']