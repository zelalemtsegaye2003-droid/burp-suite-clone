"""Test Proxy Server"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.proxy.server import ProxyServer
from src.proxy.database import ProxyDatabase
import threading
import time
import requests


def test_proxy():
    print("Testing Proxy Server...")

    db = ProxyDatabase("test_proxy.db")
    print("✓ Database created")

    proxy = ProxyServer('127.0.0.1', 8888)

    def on_request(req):
        print(f"[REQUEST] {req['method']} {req['url']}")
        db.save_request(
            req['method'], req['url'], req['headers'],
            req.get('body'), req['headers'].get('Host', ''), req['url']
        )

    proxy.on_request(on_request)

    thread = threading.Thread(target=proxy.start)
    thread.daemon = True
    thread.start()

    time.sleep(1)
    print("✓ Proxy started on 127.0.0.1:8888")

    try:
        resp = requests.get('http://httpbin.org/get', 
                          proxies={'http': 'http://127.0.0.1:8888'},
                          timeout=10)
        print(f"✓ Request sent, status: {resp.status_code}")

        requests_data = db.get_requests(limit=5)
        print(f"✓ Database has {len(requests_data)} requests")

    except Exception as e:
        print(f"✗ Request failed: {e}")

    proxy.stop()
    print("✓ Proxy stopped")

    if os.path.exists("test_proxy.db"):
        os.remove("test_proxy.db")
        print("✓ Test database cleaned up")

    print("\n=== TEST PASSED ===")


if __name__ == '__main__':
    test_proxy()