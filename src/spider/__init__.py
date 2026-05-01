"""Spider/Crawler Module"""
from .crawler import Spider, URLExtractor, CrawlResult, CrawlConfig
from .robots import RobotsChecker, RobotsTxtParser
from .advanced import FormDetector, FormAutoFiller, SiteMapGenerator, AdvancedSpider, SiteMapNode
from .session import SessionManager, AuthHandler, SpiderWithSession, SpiderSession

__all__ = [
    'Spider', 'URLExtractor', 'CrawlResult', 'CrawlConfig',
    'RobotsChecker', 'RobotsTxtParser',
    'FormDetector', 'FormAutoFiller', 'SiteMapGenerator', 'AdvancedSpider', 'SiteMapNode',
    'SessionManager', 'AuthHandler', 'SpiderWithSession', 'SpiderSession'
]