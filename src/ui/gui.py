"""
Burp Clone - Full PyQt6 GUI
A web application penetration testing toolkit
"""
import sys
import os
import threading
import time
from datetime import datetime
from typing import Optional, List, Dict
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

# WebEngine is optional - only import if available
try:
    from PyQt6.QtWebEngineWidgets import *
    from PyQt6.QtWebEngineCore import *
    HAS_WEBENGINE = True
except ImportError:
    HAS_WEBENGINE = False

# Set up path to import from src
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.proxy import HTTPSProxy, ProxyDatabase, PassiveScanner
from src.spider import Spider, CrawlConfig
from src.scanner import ScannerEngine, get_all_scanners, IssueType, Severity
from src.intruder import Intruder, AttackMode
from src.repeater import Repeater, RepeaterRequest
from src.utils import UtilitiesSuite
from src.core.scope import TargetManager, ScopeManager


class BurpCloneGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Burp Clone v1.0 - Penetration Testing Tool")
        self.setGeometry(100, 100, 1400, 900)

        self.proxy_server = None
        self.proxy_thread = None
        self.db = ProxyDatabase()
        self.utils = UtilitiesSuite()
        self.repeater = Repeater()
        self.intruder = Intruder()
        self.passive_scanner = PassiveScanner()
        self.target_manager = TargetManager()

        self.setup_ui()
        self.setup_menu()

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)

        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.TabPosition.West)
        self.tabs.setMovable(True)

        self.proxy_tab = ProxyTab(self)
        self.spider_tab = SpiderTab(self)
        self.scanner_tab = ScannerTab(self)
        self.intruder_tab = IntruderTab(self)
        self.repeater_tab = RepeaterTab(self)
        self.decoder_tab = DecoderTab(self)
        self.target_tab = TargetTab(self)

        self.tabs.addTab(self.proxy_tab, "💂 Proxy")
        self.tabs.addTab(self.spider_tab, "🕷️ Spider")
        self.tabs.addTab(self.scanner_tab, "🔍 Scanner")
        self.tabs.addTab(self.intruder_tab, "💥 Intruder")
        self.tabs.addTab(self.repeater_tab, "📡 Repeater")
        self.tabs.addTab(self.decoder_tab, "🔐 Decoder")
        self.tabs.addTab(self.target_tab, "🎯 Target")

        layout.addWidget(self.tabs)

        self.statusBar().showMessage("Ready")

    def setup_menu(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("File")
        file_menu.addAction("New Project", self.new_project)
        file_menu.addAction("Open Project", self.open_project)
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close)

        proxy_menu = menubar.addMenu("Proxy")
        proxy_menu.addAction("Start Proxy", self.start_proxy)
        proxy_menu.addAction("Stop Proxy", self.stop_proxy)
        proxy_menu.addSeparator()
        proxy_menu.addAction("Toggle Intercept", self.toggle_intercept)

        tools_menu = menubar.addMenu("Tools")
        tools_menu.addAction("Run Spider", lambda: self.tabs.setCurrentWidget(self.spider_tab))
        tools_menu.addAction("Run Scanner", lambda: self.tabs.setCurrentWidget(self.scanner_tab))

        help_menu = menubar.addMenu("Help")
        help_menu.addAction("About", self.show_about)

    def new_project(self):
        QMessageBox.information(self, "New Project", "New project created")

    def open_project(self):
        QMessageBox.information(self, "Open Project", "Open project dialog")

    def start_proxy(self):
        if not self.proxy_server:
            self.proxy_server = HTTPSProxy('127.0.0.1', 8080, "proxy_history.db")
            self.proxy_thread = threading.Thread(target=self.proxy_server.start)
            self.proxy_thread.daemon = True
            self.proxy_thread.start()
            self.statusBar().showMessage("Proxy started on 127.0.0.1:8080")

    def stop_proxy(self):
        if self.proxy_server:
            self.proxy_server.stop()
            self.proxy_server = None
            self.statusBar().showMessage("Proxy stopped")

    def toggle_intercept(self):
        if self.proxy_server:
            current = self.proxy_server.intercept_mode
            self.proxy_server.set_intercept_mode(not current)
            self.statusBar().showMessage(f"Intercept: {'ON' if not current else 'OFF'}")

    def toggle_passive_scan(self, checked):
        if self.proxy_server:
            self.proxy_server.set_passive_scan(checked)
            self.statusBar().showMessage(f"Passive Scanner: {'ON' if checked else 'OFF'}")

    def show_about(self):
        QMessageBox.about(self, "About Burp Clone",
                         "Burp Clone v1.0\n\nWeb Application Penetration Testing Toolkit\n\nBuilt with Python and PyQt6")


class ProxyTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        layout = QHBoxLayout(self)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels(["#", "Method", "URL", "Status", "Length", "Time"])
        self.history_table.doubleClicked.connect(self.show_request_detail)

        left_layout.addWidget(QLabel("Request History"))
        left_layout.addWidget(self.history_table)

        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶ Start")
        self.start_btn.clicked.connect(self.start_proxy)
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.clicked.connect(self.stop_proxy)
        self.intercept_btn = QPushButton("🔄 Intercept: OFF")
        self.intercept_btn.setCheckable(True)
        self.passive_btn = QPushButton("👁 Passive: OFF")
        self.passive_btn.setCheckable(True)
        self.passive_btn.clicked.connect(self.toggle_passive_scan)
        self.clear_btn = QPushButton("Clear")

        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.intercept_btn)
        button_layout.addWidget(self.passive_btn)
        button_layout.addWidget(self.clear_btn)
        left_layout.addLayout(button_layout)

        left_layout.addWidget(QLabel("Passive Scan Issues"))
        self.passive_issues_table = QTableWidget()
        self.passive_issues_table.setColumnCount(4)
        self.passive_issues_table.setHorizontalHeaderLabels(["#", "Issue", "Severity", "URL"])
        left_layout.addWidget(self.passive_issues_table)

        left_layout.addWidget(QLabel("Request History"))
        left_layout.addWidget(self.history_table)
        self.response_detail = QTextEdit()
        self.response_detail.setReadOnly(True)
        right_layout.addWidget(self.response_detail)

        layout.addWidget(right_panel, 1)

    def start_proxy(self):
        self.parent.start_proxy()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_proxy(self):
        self.parent.stop_proxy()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def show_request_detail(self):
        row = self.history_table.currentRow()
        if row >= 0:
            url = self.history_table.item(row, 2).text()
            self.request_detail.setPlainText(f"GET {url} HTTP/1.1\nHost: example.com")


class SpiderTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.spider = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        top_layout = QHBoxLayout()
        top_layout.addWidget(QLabel("Start URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://example.com")
        top_layout.addWidget(self.url_input, 1)

        self.start_btn = QPushButton("▶ Start Spider")
        self.start_btn.clicked.connect(self.start_spider)
        top_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.clicked.connect(self.stop_spider)
        self.stop_btn.setEnabled(False)
        top_layout.addWidget(self.stop_btn)

        layout.addLayout(top_layout)

        options_layout = QHBoxLayout()
        options_layout.addWidget(QLabel("Max Pages:"))
        self.max_pages = QSpinBox()
        self.max_pages.setValue(100)
        options_layout.addWidget(self.max_pages)

        options_layout.addWidget(QLabel("Max Depth:"))
        self.max_depth = QSpinBox()
        self.max_depth.setValue(3)
        options_layout.addWidget(self.max_depth)

        options_layout.addWidget(QLabel("Threads:"))
        self.threads = QSpinBox()
        self.threads.setValue(5)
        options_layout.addWidget(self.threads)

        options_layout.addStretch()
        layout.addLayout(options_layout)

        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["URL", "Status", "Title", "Links"])
        layout.addWidget(self.results_table)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(150)
        layout.addWidget(QLabel("Spider Log:"))
        layout.addWidget(self.log_output)

    def start_spider(self):
        url = self.url_input.text()
        if not url:
            QMessageBox.warning(self, "Warning", "Please enter a URL")
            return

        config = CrawlConfig(
            max_pages=self.max_pages.value(),
            max_depth=self.max_depth.value()
        )
        self.spider = Spider(url, config)

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.log_output.append(f"[*] Starting spider on {url}")

        thread = threading.Thread(target=self.run_spider)
        thread.start()

    def run_spider(self):
        def progress(current, queue, url):
            self.progress.setValue(current)
            self.log_output.append(f"[*] Crawled: {url}")

        results = self.spider.crawl(progress)

        self.results_table.setRowCount(len(results))
        for i, result in enumerate(results):
            self.results_table.setItem(i, 0, QTableWidgetItem(result.url))
            self.results_table.setItem(i, 1, QTableWidgetItem(str(result.status_code)))
            self.results_table.setItem(i, 2, QTableWidgetItem(result.title or ""))
            self.results_table.setItem(i, 3, QTableWidgetItem(str(len(result.links))))

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.log_output.append(f"[+] Spider complete: {len(results)} pages")

    def stop_spider(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.log_output.append("[*] Spider stopped")


class ScannerTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.scanner_engine = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        top_layout = QHBoxLayout()
        top_layout.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://example.com/page?id=1")
        top_layout.addWidget(self.url_input, 1)

        self.scan_btn = QPushButton("🔍 Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        top_layout.addWidget(self.scan_btn)

        layout.addLayout(top_layout)

        checkboxes_layout = QHBoxLayout()
        self.xss_check = QCheckBox("XSS")
        self.xss_check.setChecked(True)
        self.sqli_check = QCheckBox("SQLi")
        self.sqli_check.setChecked(True)
        self.ssrf_check = QCheckBox("SSRF")
        self.ssrf_check.setChecked(True)
        self.xxe_check = QCheckBox("XXE")
        self.xxe_check.setChecked(True)
        self.idor_check = QCheckBox("IDOR")
        self.idor_check.setChecked(True)

        checkboxes_layout.addWidget(self.xss_check)
        checkboxes_layout.addWidget(self.sqli_check)
        checkboxes_layout.addWidget(self.ssrf_check)
        checkboxes_layout.addWidget(self.xxe_check)
        checkboxes_layout.addWidget(self.idor_check)
        checkboxes_layout.addStretch()
        layout.addLayout(checkboxes_layout)

        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(["#", "Issue", "Severity", "URL", "Parameter", "Confidence"])
        layout.addWidget(self.results_table)

        detail_layout = QHBoxLayout()
        self.issue_detail = QTextEdit()
        self.issue_detail.setReadOnly(True)
        detail_layout.addWidget(self.issue_detail)
        layout.addLayout(detail_layout)

    def start_scan(self):
        url = self.url_input.text()
        if not url:
            QMessageBox.warning(self, "Warning", "Please enter a URL")
            return

        self.scan_btn.setEnabled(False)
        self.progress.setValue(0)

        self.scanner_engine = ScannerEngine()
        for scanner in get_all_scanners():
            self.scanner_engine.register_scanner(scanner.name, scanner)

        thread = threading.Thread(target=self.run_scan, args=(url,))
        thread.start()

    def run_scan(self, url):
        result = self.scanner_engine.scan_target(url)
        issues = result.issues

        self.results_table.setRowCount(len(issues))
        for i, issue in enumerate(issues):
            self.results_table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
            self.results_table.setItem(i, 1, QTableWidgetItem(issue.name))
            self.results_table.setItem(i, 2, QTableWidgetItem(issue.severity.value))
            self.results_table.setItem(i, 3, QTableWidgetItem(issue.url))
            self.results_table.setItem(i, 4, QTableWidgetItem(issue.parameter or ""))
            self.results_table.setItem(i, 5, QTableWidgetItem(issue.confidence))

        self.progress.setValue(100)
        self.scan_btn.setEnabled(True)


class IntruderTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Request"))
        self.request_input = QTextEdit()
        self.request_input.setPlaceholderText("GET /path§param§ HTTP/1.1\nHost: example.com")
        self.request_input.setMaximumHeight(150)
        layout.addWidget(self.request_input)

        options_layout = QHBoxLayout()
        options_layout.addWidget(QLabel("Attack Type:"))
        self.attack_type = QComboBox()
        self.attack_type.addItems(["Sniper", "Battering Ram", "Pitchfork", "Cluster Bomb"])
        options_layout.addWidget(self.attack_type)

        options_layout.addWidget(QLabel("Target:"))
        self.target_url = QLineEdit()
        self.target_url.setPlaceholderText("http://example.com")
        options_layout.addWidget(self.target_url, 1)

        layout.addLayout(options_layout)

        payload_layout = QHBoxLayout()
        payload_layout.addWidget(QLabel("Payloads (one per line):"))
        layout.addLayout(payload_layout)

        self.payload_input = QTextEdit()
        self.payload_input.setPlaceholderText("admin\ntest\nguest\nroot")
        self.payload_input.setMaximumHeight(100)
        layout.addWidget(self.payload_input)

        self.attack_btn = QPushButton("💥 Start Attack")
        self.attack_btn.clicked.connect(self.start_attack)
        layout.addWidget(self.attack_btn)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["#", "Payload", "Status", "Length", "Time"])
        layout.addWidget(self.results_table)

    def start_attack(self):
        request_text = self.request_input.toPlainText()
        target = self.target_url.text()

        if not request_text or not target:
            QMessageBox.warning(self, "Warning", "Please enter request and target")
            return

        payloads = self.payload_input.toPlainText().split('\n')
        payloads = [p.strip() for p in payloads if p.strip()]

        self.intruder = Intruder()
        self.intruder.set_request(request_text)

        for payload in payloads:
            self.intruder.set_payloads('param', payloads)

        mode = AttackMode[self.attack_type.currentText().replace(' ', '_').upper()]
        self.intruder.set_attack_mode(mode)

        self.attack_btn.setEnabled(False)
        results = self.intruder.execute()

        self.results_table.setRowCount(len(results))
        for i, result in enumerate(results):
            self.results_table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
            self.results_table.setItem(i, 1, QTableWidgetItem(result.payload[:30]))
            self.results_table.setItem(i, 2, QTableWidgetItem(str(result.status_code)))
            self.results_table.setItem(i, 3, QTableWidgetItem(str(result.response_length)))
            self.results_table.setItem(i, 4, QTableWidgetItem(str(result.response_time_ms)))

        self.attack_btn.setEnabled(True)


class RepeaterTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.current_request = None
        self.init_ui()

    def init_ui(self):
        layout = QHBoxLayout(self)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)

        left_layout.addWidget(QLabel("Request"))

        request_layout = QHBoxLayout()
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
        request_layout.addWidget(self.method_combo)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://example.com/api")
        request_layout.addWidget(self.url_input, 1)

        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_request)
        request_layout.addWidget(self.send_btn)

        left_layout.addLayout(request_layout)

        self.request_editor = QTextEdit()
        self.request_editor.setPlaceholderText("Headers and body...")
        left_layout.addWidget(self.request_editor)

        layout.addWidget(left_panel, 1)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        right_layout.addWidget(QLabel("Response"))

        self.response_view = QTabWidget()

        self.response_raw = QTextEdit()
        self.response_raw.setReadOnly(True)
        self.response_view.addTab(self.response_raw, "Raw")

        self.response_parsed = QTextEdit()
        self.response_parsed.setReadOnly(True)
        self.response_view.addTab(self.response_parsed, "Parsed")

        self.response_hex = QTextEdit()
        self.response_hex.setReadOnly(True)
        self.response_view.addTab(self.response_hex, "Hex")

        right_layout.addWidget(self.response_view)

        layout.addWidget(right_panel, 1)

    def send_request(self):
        method = self.method_combo.currentText()
        url = self.url_input.text()

        if not url:
            QMessageBox.warning(self, "Warning", "Please enter a URL")
            return

        self.send_btn.setEnabled(False)
        self.response_raw.setPlainText("Sending request...")

        thread = threading.Thread(target=self.do_request, args=(method, url))
        thread.start()

    def do_request(self, method, url):
        try:
            from src.repeater import RepeaterRequest
            req = RepeaterRequest(
                id=0,
                name=f"{method} {url[:30]}",
                method=method,
                url=url,
                headers={},
                body=self.request_editor.toPlainText().encode()
            )

            response, status, headers, time_ms = self.parent.repeater.send(req)

            self.response_raw.setPlainText(f"HTTP/1.1 {status} OK\nTime: {time_ms}ms\n\n" + response.decode('utf-8', errors='replace')[:5000])

            parsed_text = f"Status: {status}\nTime: {time_ms}ms\n\nHeaders:\n"
            for k, v in headers.items():
                parsed_text += f"{k}: {v}\n"
            self.response_parsed.setPlainText(parsed_text)

            self.response_hex.setPlainText(response.hex()[:2000])

        except Exception as e:
            self.response_raw.setPlainText(f"Error: {str(e)}")

        self.send_btn.setEnabled(True)


class DecoderTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        input_layout = QHBoxLayout()
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter text to encode/decode...")
        input_layout.addWidget(self.input_text, 1)
        layout.addLayout(input_layout)

        buttons_layout = QHBoxLayout()

        self.decode_btn = QPushButton("Decode")
        self.decode_btn.clicked.connect(self.decode)
        buttons_layout.addWidget(self.decode_btn)

        self.encode_btn = QPushButton("Encode")
        self.encode_btn.clicked.connect(self.encode)
        buttons_layout.addWidget(self.encode_btn)

        self.hash_btn = QPushButton("Hash")
        self.hash_btn.clicked.connect(self.hash)
        buttons_layout.addWidget(self.hash_btn)

        buttons_layout.addStretch()
        layout.addLayout(buttons_layout)

        options_layout = QHBoxLayout()
        options_layout.addWidget(QLabel("Type:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Base64", "URL", "Hex", "HTML", "Unicode", "MD5", "SHA256"])
        options_layout.addWidget(self.type_combo)
        options_layout.addStretch()
        layout.addLayout(options_layout)

        layout.addWidget(QLabel("Output:"))
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        layout.addWidget(self.output_text, 1)

    def decode(self):
        data = self.input_text.toPlainText()
        enc_type = self.type_combo.currentText().lower()

        if enc_type in ['md5', 'sha256']:
            self.output_text.setPlainText("Hash functions cannot be decoded")
            return

        result, success = self.parent.utils.decode(data, enc_type)
        self.output_text.setPlainText(result)

    def encode(self):
        data = self.input_text.toPlainText()
        enc_type = self.type_combo.currentText().lower()

        if enc_type in ['md5', 'sha256']:
            result = self.parent.utils.hash(data, enc_type)
            self.output_text.setPlainText(result)
            return

        result, success = self.parent.utils.encode(data, enc_type)
        self.output_text.setPlainText(result)

    def hash(self):
        data = self.input_text.toPlainText()
        enc_type = self.type_combo.currentText().lower()

        result = self.parent.utils.hash_all(data)
        self.output_text.setPlainText(json.dumps(result, indent=2))


import json


class TargetTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("🎯 Scope Management"))

        include_layout = QHBoxLayout()
        include_layout.addWidget(QLabel("Include (regex):"))
        self.include_input = QLineEdit()
        self.include_input.setPlaceholderText(r".*\.example\.com.*")
        include_layout.addWidget(self.include_input, 1)
        self.add_include_btn = QPushButton("+ Add")
        self.add_include_btn.clicked.connect(self.add_include)
        include_layout.addWidget(self.add_include_btn)
        layout.addLayout(include_layout)

        self.include_list = QListWidget()
        layout.addWidget(QLabel("Included Patterns:"))
        layout.addWidget(self.include_list)

        exclude_layout = QHBoxLayout()
        exclude_layout.addWidget(QLabel("Exclude (regex):"))
        self.exclude_input = QLineEdit()
        self.exclude_input.setPlaceholderText(".*logout.*")
        exclude_layout.addWidget(self.exclude_input, 1)
        self.add_exclude_btn = QPushButton("+ Add")
        self.add_exclude_btn.clicked.connect(self.add_exclude)
        exclude_layout.addWidget(self.add_exclude_btn)
        layout.addLayout(exclude_layout)

        self.exclude_list = QListWidget()
        layout.addWidget(QLabel("Excluded Patterns:"))
        layout.addWidget(self.exclude_list)

        scope_buttons = QHBoxLayout()
        self.clear_scope_btn = QPushButton("Clear All")
        self.clear_scope_btn.clicked.connect(self.clear_scope)
        scope_buttons.addWidget(self.clear_scope_btn)
        scope_buttons.addStretch()
        layout.addLayout(scope_buttons)

        layout.addWidget(QLabel("📊 Site Map"))
        self.sitemap_table = QTableWidget()
        self.sitemap_table.setColumnCount(4)
        self.sitemap_table.setHorizontalHeaderLabels(["Host", "URL", "Status", "Issues"])
        layout.addWidget(self.sitemap_table)

        self.refresh_sitemap_btn = QPushButton("🔄 Refresh Site Map")
        self.refresh_sitemap_btn.clicked.connect(self.refresh_sitemap)
        layout.addWidget(self.refresh_sitemap_btn)

        stats_layout = QHBoxLayout()
        self.stats_label = QLabel("Stats: 0 hosts, 0 URLs")
        stats_layout.addWidget(self.stats_label)
        stats_layout.addStretch()
        layout.addLayout(stats_layout)

    def add_include(self):
        pattern = self.include_input.text()
        if pattern:
            self.parent.target_manager.add_target(pattern)
            self.include_list.addItem(pattern)
            self.include_input.clear()

    def add_exclude(self):
        pattern = self.exclude_input.text()
        if pattern:
            self.parent.target_manager.add_exclusion(pattern)
            self.exclude_list.addItem(pattern)
            self.exclude_input.clear()

    def clear_scope(self):
        self.parent.target_manager.scope_manager.clear()
        self.include_list.clear()
        self.exclude_list.clear()
        self.sitemap_table.setRowCount(0)
        self.stats_label.setText("Stats: 0 hosts, 0 URLs")

    def refresh_sitemap(self):
        urls = self.parent.target_manager.sitemap.nodes

        self.sitemap_table.setRowCount(len(urls))
        for i, (url, node) in enumerate(urls.items()):
            self.sitemap_table.setItem(i, 0, QTableWidgetItem(node.host))
            self.sitemap_table.setItem(i, 1, QTableWidgetItem(url))
            self.sitemap_table.setItem(i, 2, QTableWidgetItem(str(node.status_code)))
            self.sitemap_table.setItem(i, 3, QTableWidgetItem(str(node.issues)))

        summary = self.parent.target_manager.get_sitemap_summary()
        self.stats_label.setText(f"Stats: {summary['hosts']} hosts, {summary['total_urls']} URLs")


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
    app.setPalette(palette)

    window = BurpCloneGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()