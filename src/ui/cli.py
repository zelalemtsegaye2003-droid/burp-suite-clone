"""CLI Interface for Burp Clone"""
import sys
import threading
import time
import readline
from typing import Optional
from ..proxy.server import ProxyServer
from ..proxy.https_proxy import HTTPSProxy
from ..proxy.database import ProxyDatabase
from ..proxy.filter import FilterManager
from .history import HistoryViewer, HistoryTableDisplay


class BurpCloneCLI:
    def __init__(self):
        self.proxy: Optional[HTTPSProxy] = None
        self.db = ProxyDatabase("proxy_history.db")
        self.history = HistoryViewer("proxy_history.db")
        self.filter_manager = FilterManager()
        self.running = False
        self.intercepting = False

    def start_proxy(self, host: str = '127.0.0.1', port: int = 8080):
        self.proxy = HTTPSProxy(host, port, "proxy_history.db", filter_manager=self.filter_manager)
        thread = threading.Thread(target=self.proxy.start)
        thread.daemon = True
        thread.start()
        self.running = True
        print(f"[*] Proxy started on {host}:{port}")

    def stop_proxy(self):
        if self.proxy:
            self.proxy.stop()
            self.running = False
            print("[*] Proxy stopped")

    def show_history(self, limit: int = 20):
        items = self.history.get_items(limit=limit)
        print(HistoryTableDisplay.format_table(items))

    def show_request_detail(self, item_id: int):
        detail = self.history.get_item_detail(item_id)
        if detail:
            print(HistoryTableDisplay.format_detail(detail))
        else:
            print(f"Request #{item_id} not found")

    def search_requests(self, keyword: str):
        results = self.history.search(keyword)
        print(HistoryTableDisplay.format_table(results))

    def add_filter_domain(self, domain: str):
        self.filter_manager.add_blacklist_domain(domain)
        print(f"[+] Added {domain} to blacklist")

    def add_filter_method(self, method: str):
        self.filter_manager.add_blacklist_method(method)
        print(f"[+] Added {method} to method blacklist")

    def toggle_intercept(self):
        self.intercepting = not self.intercepting
        if self.proxy:
            self.proxy.set_intercept_mode(self.intercepting)
        print(f"[*] Intercept mode: {'ON' if self.intercepting else 'OFF'}")

    def set_upstream_proxy(self, host: str, port: int, username: str = None, password: str = None):
        if self.proxy:
            self.proxy.set_upstream_proxy(host, port, username, password)
            print(f"[*] Upstream proxy set: {host}:{port}")

    def help(self):
        print("""
Burp Clone Commands:
==================
proxy start [host] [port]  - Start proxy server (default: 127.0.0.1:8080)
proxy stop                  - Stop proxy server
history [limit]             - Show request history (default: 20)
detail <id>                 - Show request/response details
search <keyword>            - Search requests
intercept                   - Toggle intercept mode
filter domain <domain>      - Add domain to blacklist
filter method <method>     - Add method to blacklist (e.g., TRACE)
upstream <host> <port>     - Set upstream proxy
clear                       - Clear history
help                        - Show this help
quit                        - Exit
""")

    def run(self):
        print("""
╔═══════════════════════════════════════╗
║       Burp Clone v0.1.0              ║
║   Web App Penetration Testing Tool   ║
╚═══════════════════════════════════════╝
Type 'help' for commands.
""")
        self.help()

        while True:
            try:
                cmd = input("\nburp> ").strip()
                if not cmd:
                    continue

                parts = cmd.split()
                command = parts[0].lower()

                if command == 'proxy' and len(parts) > 1:
                    if parts[1] == 'start':
                        host = parts[2] if len(parts) > 2 else '127.0.0.1'
                        port = int(parts[3]) if len(parts) > 3 else 8080
                        self.start_proxy(host, port)
                    elif parts[1] == 'stop':
                        self.stop_proxy()
                    else:
                        print("Usage: proxy start [host] [port]")

                elif command == 'history':
                    limit = int(parts[1]) if len(parts) > 1 else 20
                    self.show_history(limit)

                elif command == 'detail':
                    if len(parts) > 1:
                        self.show_request_detail(int(parts[1]))
                    else:
                        print("Usage: detail <id>")

                elif command == 'search':
                    if len(parts) > 1:
                        self.search_requests(' '.join(parts[1:]))
                    else:
                        print("Usage: search <keyword>")

                elif command == 'intercept':
                    self.toggle_intercept()

                elif command == 'filter' and len(parts) > 2:
                    if parts[1] == 'domain':
                        self.add_filter_domain(parts[2])
                    elif parts[1] == 'method':
                        self.add_filter_method(parts[2].upper())
                    else:
                        print("Usage: filter <domain|method> <value>")

                elif command == 'upstream' and len(parts) > 2:
                    username = parts[3] if len(parts) > 3 else None
                    password = parts[4] if len(parts) > 4 else None
                    self.set_upstream_proxy(parts[1], int(parts[2]), username, password)

                elif command == 'clear':
                    self.history.clear_all()
                    print("[*] History cleared")

                elif command == 'help':
                    self.help()

                elif command == 'quit' or command == 'exit':
                    self.stop_proxy()
                    print("[*] Goodbye!")
                    break

                else:
                    print(f"Unknown command: {command}. Type 'help' for help.")

            except KeyboardInterrupt:
                print("\n[*] Use 'quit' to exit")
            except Exception as e:
                print(f"Error: {e}")


def main():
    cli = BurpCloneCLI()
    cli.run()


if __name__ == '__main__':
    main()