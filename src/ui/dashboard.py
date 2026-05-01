"""Dashboard for Burp Clone"""
import os
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class DashboardStats:
    proxy_requests: int = 0
    spider_pages: int = 0
    scanner_issues: int = 0
    intruder_requests: int = 0
    repeater_requests: int = 0
    start_time: datetime = None


class Dashboard:
    def __init__(self):
        self.stats = DashboardStats()
        self.stats.start_time = datetime.now()
        self.sections = []

    def add_section(self, name: str, content: str):
        self.sections.append((name, content))

    def update_stats(self, key: str, value: int):
        if hasattr(self.stats, key):
            setattr(self.stats, key, value)

    def increment(self, key: str):
        if hasattr(self.stats, key):
            current = getattr(self.stats, key)
            setattr(self.stats, key, current + 1)

    def render(self):
        uptime = datetime.now() - self.stats.start_time
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)

        os.system('cls' if os.name == 'nt' else 'clear')

        print("╔══════════════════════════════════════════════════════════════════╗")
        print("║                    BURP CLONE - DASHBOARD                        ║")
        print("╠══════════════════════════════════════════════════════════════════╣")
        print(f"║  Uptime: {hours}h {minutes}m {seconds}s" + " " * (57 - len(f"{hours}h {minutes}m {seconds}s")) + "║")
        print("╠══════════════════════════════════════════════════════════════════╣")
        print("║  TOOLS                                                            ║")
        print("╟──────────────────────────────────────────────────────────────────╢")
        print(f"║  [1] Proxy Server    │ Requests: {self.stats.proxy_requests:>6}                            ║")
        print(f"║  [2] Spider          │ Pages: {self.stats.spider_pages:>6}                              ║")
        print(f"║  [3] Scanner         │ Issues: {self.stats.scanner_issues:>6}                             ║")
        print(f"║  [4] Intruder        │ Sent: {self.stats.intruder_requests:>6}                               ║")
        print(f"║  [5] Repeater       │ Sent: {self.stats.repeater_requests:>6}                               ║")
        print("╠══════════════════════════════════════════════════════════════════╣")
        print("║  COMMANDS                                                         ║")
        print("╟──────────────────────────────────────────────────────────────────╢")
        print("║  proxy start <port>  - Start proxy server                        ║")
        print("║  scan <url>          - Run vulnerability scan                   ║")
        print("║  spider <url>        - Start web spider                          ║")
        print("║  repeater <method> <url> - Send single request                   ║")
        print("║  decoder <data> <type> - Decode data                            ║")
        print("║  encoder <data> <type> - Encode data                            ║")
        print("║  hash <data> <algo>  - Generate hash                            ║")
        print("║  quit / exit         - Exit application                         ║")
        print("╚══════════════════════════════════════════════════════════════════╝")

    def run_interactive(self):
        from src.proxy import HTTPSProxy, ProxyDatabase, FilterManager
        from src.scanner import ScannerEngine, get_all_scanners
        from src.spider import Spider, CrawlConfig
        from src.repeater import Repeater, RepeaterRequest
        from src.utils import UtilitiesSuite

        proxy = None
        proxy_thread = None

        while True:
            self.render()
            print("\n> ", end="")
            try:
                cmd = input().strip().split()
                if not cmd:
                    continue

                action = cmd[0].lower()

                if action in ['quit', 'exit']:
                    if proxy:
                        proxy.stop()
                    print("Goodbye!")
                    break

                elif action == 'proxy' and len(cmd) > 1:
                    if cmd[1] == 'start':
                        port = int(cmd[2]) if len(cmd) > 2 else 8080
                        proxy = HTTPSProxy('127.0.0.1', port)
                        proxy_thread = threading.Thread(target=proxy.start)
                        proxy_thread.daemon = True
                        proxy_thread.start()
                        print(f"Proxy started on port {port}")
                        time.sleep(1)

                elif action == 'scan' and len(cmd) > 1:
                    target = cmd[1]
                    engine = ScannerEngine()
                    for scanner in get_all_scanners():
                        engine.register_scanner(scanner.name, scanner)
                    result = engine.scan_target(target)
                    self.stats.scanner_issues = len(result.issues)
                    print(f"Scan complete: {len(result.issues)} issues found")

                elif action == 'spider' and len(cmd) > 1:
                    target = cmd[1]
                    config = CrawlConfig(max_pages=50, max_depth=2)
                    spider = Spider(target, config)
                    results = spider.crawl()
                    self.stats.spider_pages = len(results)
                    print(f"Spider complete: {len(results)} pages")

                elif action == 'decoder' and len(cmd) > 3:
                    data, enc_type = cmd[1], cmd[2]
                    utils = UtilitiesSuite()
                    result, _ = utils.decode(data, enc_type)
                    print(f"Result: {result[:100]}")

                elif action == 'encoder' and len(cmd) > 3:
                    data, enc_type = cmd[1], cmd[2]
                    utils = UtilitiesSuite()
                    result, _ = utils.encode(data, enc_type)
                    print(f"Result: {result[:100]}")

                elif action == 'hash' and len(cmd) > 2:
                    data, algo = cmd[1], cmd[2]
                    utils = UtilitiesSuite()
                    result = utils.hash(data, algo)
                    print(f"{algo.upper()} hash: {result}")

                elif action == 'help':
                    pass

                else:
                    print("Unknown command. Type 'help' for available commands.")

            except KeyboardInterrupt:
                print("\nUse 'quit' to exit")
            except Exception as e:
                print(f"Error: {e}")


class WebDashboard:
    def __init__(self, host='127.0.0.1', port=5000):
        self.host = host
        self.port = port
        self.stats = DashboardStats()

    def start(self):
        try:
            from flask import Flask, render_template_string, request, jsonify

            app = Flask(__name__)

            HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Burp Clone Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', monospace; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
        .header { background: #161b22; padding: 20px; border-bottom: 1px solid #30363d; }
        .header h1 { color: #58a6ff; font-size: 24px; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 20px; }
        .stat-card h3 { color: #8b949e; font-size: 14px; margin-bottom: 10px; }
        .stat-card .value { font-size: 32px; color: #58a6ff; }
        .tool { background: #161b22; border: 1px solid #30363d; border-radius: 6px; margin-bottom: 20px; }
        .tool-header { padding: 15px 20px; border-bottom: 1px solid #30363d; display: flex; justify-content: space-between; align-items: center; }
        .tool-header h2 { color: #c9d1d9; }
        .tool-body { padding: 20px; }
        form { display: flex; gap: 10px; }
        input, select { background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 10px; border-radius: 4px; flex: 1; }
        button { background: #238636; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        button:hover { background: #2ea043; }
        .result { margin-top: 15px; background: #0d1117; padding: 15px; border-radius: 4px; white-space: pre-wrap; font-family: monospace; font-size: 12px; max-height: 200px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Burp Clone Dashboard</h1>
    </div>
    <div class="container">
        <div class="stats">
            <div class="stat-card"><h3>Proxy Requests</h3><div class="value" id="proxy">0</div></div>
            <div class="stat-card"><h3>Spider Pages</h3><div class="value" id="spider">0</div></div>
            <div class="stat-card"><h3>Scanner Issues</h3><div class="value" id="scanner">0</div></div>
            <div class="stat-card"><h3>Intruder Requests</h3><div class="value" id="intruder">0</div></div>
        </div>

        <div class="tool">
            <div class="tool-header"><h2>🔍 Vulnerability Scanner</h2></div>
            <div class="tool-body">
                <form action="/scan" method="POST">
                    <input type="text" name="url" placeholder="Enter target URL (e.g., http://example.com)">
                    <button type="submit">Scan</button>
                </form>
                <div class="result" id="scan-result"></div>
            </div>
        </div>

        <div class="tool">
            <div class="tool-header"><h2>🕷️ Spider</h2></div>
            <div class="tool-body">
                <form action="/spider" method="POST">
                    <input type="text" name="url" placeholder="Enter target URL">
                    <button type="submit">Crawl</button>
                </form>
                <div class="result" id="spider-result"></div>
            </div>
        </div>

        <div class="tool">
            <div class="tool-header"><h2>🔐 Utilities</h2></div>
            <div class="tool-body">
                <form action="/utils" method="POST">
                    <select name="action">
                        <option value="decode_base64">Decode Base64</option>
                        <option value="encode_base64">Encode Base64</option>
                        <option value="decode_url">Decode URL</option>
                        <option value="encode_url">Encode URL</option>
                        <option value="hash_md5">MD5 Hash</option>
                        <option value="hash_sha256">SHA256 Hash</option>
                    </select>
                    <input type="text" name="data" placeholder="Enter data">
                    <button type="submit">Execute</button>
                </form>
                <div class="result" id="utils-result"></div>
            </div>
        </div>
    </div>

    <script>
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const formData = new FormData(form);
                const endpoint = form.action.split('/').pop();
                const resultDiv = document.getElementById(endpoint + '-result');

                resultDiv.textContent = 'Processing...';

                try {
                    const response = await fetch('/' + endpoint, {
                        method: 'POST',
                        body: formData
                    });
                    const data = await response.json();
                    resultDiv.textContent = JSON.stringify(data, null, 2);

                    if (data.proxy !== undefined) document.getElementById('proxy').textContent = data.proxy;
                    if (data.spider !== undefined) document.getElementById('spider').textContent = data.spider;
                    if (data.scanner !== undefined) document.getElementById('scanner').textContent = data.scanner;
                    if (data.intruder !== undefined) document.getElementById('intruder').textContent = data.intruder;
                } catch (err) {
                    resultDiv.textContent = 'Error: ' + err.message;
                }
            });
        });
    </script>
</body>
</html>
"""

            @app.route('/')
            def index():
                return render_template_string(HTML)

            @app.route('/scan', methods=['POST'])
            def scan():
                url = request.form.get('url', '')
                if not url:
                    return jsonify({'error': 'No URL provided'})

                from src.scanner import ScannerEngine, get_all_scanners
                engine = ScannerEngine()
                for scanner in get_all_scanners():
                    engine.register_scanner(scanner.name, scanner)

                result = engine.scan_target(url)
                self.stats.scanner_issues = len(result.issues)

                return jsonify({
                    'scanner': len(result.issues),
                    'issues': [{'name': i.name, 'severity': i.severity.value, 'url': i.url} for i in result.issues[:10]]
                })

            @app.route('/spider', methods=['POST'])
            def spider():
                url = request.form.get('url', '')
                if not url:
                    return jsonify({'error': 'No URL provided'})

                from src.spider import Spider, CrawlConfig
                config = CrawlConfig(max_pages=50, max_depth=2)
                spider = Spider(url, config)
                results = spider.crawl()
                self.stats.spider_pages = len(results)

                return jsonify({
                    'spider': len(results),
                    'pages': [{'url': r.url, 'title': r.title} for r in results[:10]]
                })

            @app.route('/utils', methods=['POST'])
            def utils():
                action = request.form.get('action', '')
                data = request.form.get('data', '')

                from src.utils import UtilitiesSuite
                utils = UtilitiesSuite()

                result = ''
                if action == 'decode_base64':
                    result, _ = utils.decode(data, 'base64')
                elif action == 'encode_base64':
                    result, _ = utils.encode(data, 'base64')
                elif action == 'decode_url':
                    result, _ = utils.decode(data, 'url')
                elif action == 'encode_url':
                    result, _ = utils.encode(data, 'url')
                elif action == 'hash_md5':
                    result = utils.hash(data, 'md5')
                elif action == 'hash_sha256':
                    result = utils.hash(data, 'sha256')

                return jsonify({'result': str(result)[:200]})

            print(f"Starting web dashboard at http://{self.host}:{self.port}")
            app.run(host=self.host, port=self.port, debug=False, use_reloader=False)

        except ImportError:
            print("Flask not installed. Running terminal dashboard instead.")
            dashboard = Dashboard()
            dashboard.run_interactive()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Burp Clone Dashboard')
    parser.add_argument('--web', action='store_true', help='Start web dashboard')
    parser.add_argument('--host', default='127.0.0.1', help='Host')
    parser.add_argument('--port', type=int, default=5000, help='Port')
    args = parser.parse_args()

    if args.web:
        WebDashboard(args.host, args.port).start()
    else:
        Dashboard().run_interactive()