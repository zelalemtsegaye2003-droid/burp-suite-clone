"""Main CLI Entry Point for Burp Clone"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
import threading
import time
from src.proxy import HTTPSProxy, ProxyDatabase, FilterManager
from src.spider import Spider, CrawlConfig
from src.scanner import ScannerEngine, get_all_scanners, IssueTracker
from src.intruder import Intruder, AttackMode
from src.repeater import Repeater
from src.utils import UtilitiesSuite
from src.ui.cli import BurpCloneCLI


class BurpCloneApp:
    def __init__(self):
        self.proxy = None
        self.db = ProxyDatabase()
        self.filter_manager = FilterManager()
        self.scanner_engine = ScannerEngine()
        self.repeater = Repeater()
        self.utils = UtilitiesSuite()

    def start_proxy(self, host='127.0.0.1', port=8080):
        self.proxy = HTTPSProxy(host, port, filter_manager=self.filter_manager)
        thread = threading.Thread(target=self.proxy.start)
        thread.daemon = True
        thread.start()
        print(f"[+] Proxy started on {host}:{port}")

    def stop_proxy(self):
        if self.proxy:
            self.proxy.stop()
            print("[+] Proxy stopped")

    def scan_target(self, target):
        for scanner in get_all_scanners():
            self.scanner_engine.register_scanner(scanner.name, scanner)

        result = self.scanner_engine.scan_target(target)
        print(f"\n[+] Scan complete: {len(result.issues)} issues found")

        summary = self.scanner_engine.get_summary()
        print(f"    Critical: {summary['by_severity']['critical']}")
        print(f"    High: {summary['by_severity']['high']}")
        print(f"    Medium: {summary['by_severity']['medium']}")
        print(f"    Low: {summary['by_severity']['low']}")
        print(f"    Info: {summary['by_severity']['info']}")

    def spider(self, target, max_pages=100, max_depth=3):
        config = CrawlConfig(max_pages=max_pages, max_depth=max_depth)
        spider = Spider(target, config)

        print(f"[*] Starting spider on {target}")

        def progress(current, queue, url):
            print(f"    {current} pages crawled, {queue} queued")

        results = spider.crawl(progress)
        print(f"\n[+] Spider complete: {len(results)} pages")

    def intruder_fuzz(self, request, payloads, mode='sniper'):
        intruder = Intruder()
        intruder.set_request(request)

        for pos, payload_list in payloads.items():
            intruder.set_payloads(pos, payload_list)

        intruder.set_attack_mode(AttackMode[mode.upper()])

        results = intruder.execute()
        print(f"[+] Intruder complete: {len(results)} requests")

        matched = sum(1 for r in results if r.matched)
        print(f"    {matched} matches found")

    def repeater_send(self, method, url, headers=None, body=None):
        from src.repeater import RepeaterRequest
        req = RepeaterRequest(
            id=0,
            name=f"{method} {url[:30]}",
            method=method,
            url=url,
            headers=headers or {},
            body=body
        )

        response, status, resp_headers, time_ms = self.repeater.send(req)
        print(f"[+] Response: {status} in {time_ms}ms")
        return response

    def decode(self, data, encoding):
        result, success = self.utils.decode(data, encoding)
        print(f"[+] Decoded: {result}")

    def encode(self, data, encoding):
        result, success = self.utils.encode(data, encoding)
        print(f"[+] Encoded: {result}")

    def hash(self, data, algorithm='md5'):
        result = self.utils.hash(data, algorithm)
        print(f"[+] {algorithm.upper()} hash: {result}")


def main():
    parser = argparse.ArgumentParser(
        description='Burp Clone - Web Application Penetration Testing Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.main_cli --proxy                   # Start proxy server
  python -m src.main_cli --scan http://target.com # Scan target
  python -m src.main_cli --spider http://target.com # Spider target
  python -m src.main_cli --repeater GET http://example.com # Send request
  python -m src.main_cli --decode "SGVsbG8=" base64 # Decode
  python -m src.main_cli --encode "Hello" base64   # Encode
  python -m src.main_cli --hash "password" md5    # Hash
  python -m src.main_cli --cli                     # Interactive CLI
        """
    )

    parser.add_argument('--proxy', action='store_true', help='Start proxy server')
    parser.add_argument('--host', default='127.0.0.1', help='Proxy host')
    parser.add_argument('--port', type=int, default=8080, help='Proxy port')
    parser.add_argument('--scan', metavar='URL', help='Scan target URL')
    parser.add_argument('--spider', metavar='URL', help='Spider target URL')
    parser.add_argument('--max-pages', type=int, default=100, help='Max pages to spider')
    parser.add_argument('--max-depth', type=int, default=3, help='Max crawl depth')
    parser.add_argument('--repeater', nargs=2, metavar=('METHOD', 'URL'), help='Send request via Repeater')
    parser.add_argument('--decode', nargs=2, metavar=('DATA', 'ENCODING'), help='Decode data')
    parser.add_argument('--encode', nargs=2, metavar=('DATA', 'ENCODING'), help='Encode data')
    parser.add_argument('--hash', nargs=2, metavar=('DATA', 'ALGORITHM'), help='Generate hash')
    parser.add_argument('--cli', action='store_true', help='Start interactive CLI')
    parser.add_argument('--version', action='store_true', help='Show version')

    args = parser.parse_args()

    if args.version:
        print("Burp Clone v1.0.0")
        print("Web Application Penetration Testing Toolkit")
        return

    app = BurpCloneApp()

    if args.proxy:
        app.start_proxy(args.host, args.port)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            app.stop_proxy()

    elif args.scan:
        app.scan_target(args.scan)

    elif args.spider:
        app.spider(args.spider, args.max_pages, args.max_depth)

    elif args.repeater:
        method, url = args.repeater
        app.repeater_send(method, url)

    elif args.decode:
        data, encoding = args.decode
        app.decode(data, encoding)

    elif args.encode:
        data, encoding = args.encode
        app.encode(data, encoding)

    elif args.hash:
        data, algorithm = args.hash
        app.hash(data, algorithm)

    elif args.cli:
        cli = BurpCloneCLI()
        cli.run()

    else:
        parser.print_help()


if __name__ == '__main__':
    main()