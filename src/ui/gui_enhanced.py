"""
Burp Clone - Enhanced PyQt6 GUI with Toolbar, Shortcuts, and Settings
A web application penetration testing toolkit
"""
import sys
import os
import threading
import time
import json
from datetime import datetime
from typing import Optional, List, Dict
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

try:
    from PyQt6.QtWebEngineWidgets import *
    from PyQt6.QtWebEngineCore import *
except ImportError:
    pass

# Set up path to import from src
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.proxy import HTTPSProxy, ProxyDatabase, PassiveScanner
from src.spider import Spider, CrawlConfig
from src.scanner import ScannerEngine, get_all_scanners, IssueType, Severity
from src.scanner.report import ReportGenerator
from src.intruder import Intruder, AttackMode
from src.repeater import Repeater, RepeaterRequest
from src.utils import UtilitiesSuite
from src.core.scope import TargetManager, ScopeManager


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.resize(500, 400)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        tabs = QTabWidget()

        proxy_tab = QWidget()
        proxy_layout = QFormLayout(proxy_tab)
        self.proxy_host = QLineEdit("127.0.0.1")
        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1, 65535)
        self.proxy_port.setValue(8080)
        self.upstream_proxy = QLineEdit()
        self.upstream_proxy.setPlaceholderText("http://proxy:8080")
        proxy_layout.addRow("Proxy Host:", self.proxy_host)
        proxy_layout.addRow("Proxy Port:", self.proxy_port)
        proxy_layout.addRow("Upstream Proxy:", self.upstream_proxy)
        tabs.addTab(proxy_tab, "Proxy")

        scanner_tab = QWidget()
        scanner_layout = QFormLayout(scanner_tab)
        self.max_threads = QSpinBox()
        self.max_threads.setRange(1, 50)
        self.max_threads.setValue(5)
        self.timeout = QSpinBox()
        self.timeout.setRange(1, 300)
        self.timeout.setValue(30)
        self.follow_redirects = QCheckBox()
        self.follow_redirects.setChecked(True)
        scanner_layout.addRow("Max Threads:", self.max_threads)
        scanner_layout.addRow("Request Timeout:", self.timeout)
        scanner_layout.addRow("Follow Redirects:", self.follow_redirects)
        tabs.addTab(scanner_tab, "Scanner")

        ui_tab = QWidget()
        ui_layout = QFormLayout(ui_tab)
        self.dark_theme = QCheckBox()
        self.dark_theme.setChecked(True)
        self.auto_save = QCheckBox()
        self.auto_save.setChecked(False)
        self.font_size = QSpinBox()
        self.font_size.setRange(8, 20)
        self.font_size.setValue(12)
        ui_layout.addRow("Dark Theme:", self.dark_theme)
        ui_layout.addRow("Auto Save:", self.auto_save)
        ui_layout.addRow("Font Size:", self.font_size)
        tabs.addTab(ui_tab, "UI")

        layout.addWidget(tabs)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_settings(self) -> Dict:
        return {
            'proxy': {
                'host': self.proxy_host.text(),
                'port': self.proxy_port.value(),
                'upstream': self.upstream_proxy.text()
            },
            'scanner': {
                'max_threads': self.max_threads.value(),
                'timeout': self.timeout.value(),
                'follow_redirects': self.follow_redirects.isChecked()
            },
            'ui': {
                'dark_theme': self.dark_theme.isChecked(),
                'auto_save': self.auto_save.isChecked(),
                'font_size': self.font_size.value()
            }
        }

    def load_settings(self, settings: Dict):
        if 'proxy' in settings:
            self.proxy_host.setText(settings['proxy'].get('host', '127.0.0.1'))
            self.proxy_port.setValue(settings['proxy'].get('port', 8080))
            self.upstream_proxy.setText(settings['proxy'].get('upstream', ''))
        if 'scanner' in settings:
            self.max_threads.setValue(settings['scanner'].get('max_threads', 5))
            self.timeout.setValue(settings['scanner'].get('timeout', 30))
            self.follow_redirects.setChecked(settings['scanner'].get('follow_redirects', True))
        if 'ui' in settings:
            self.dark_theme.setChecked(settings['ui'].get('dark_theme', True))
            self.auto_save.setChecked(settings['ui'].get('auto_save', False))
            self.font_size.setValue(settings['ui'].get('font_size', 12))


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
        self.scan_results = []

        self.settings = self.load_settings_from_file()

        self.setup_ui()
        self.setup_menu()
        self.setup_toolbar()
        self.setup_shortcuts()

    def load_settings_from_file(self) -> Dict:
        settings_file = "burp_clone_settings.json"
        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {
            'proxy': {'host': '127.0.0.1', 'port': 8080, 'upstream': ''},
            'scanner': {'max_threads': 5, 'timeout': 30, 'follow_redirects': True},
            'ui': {'dark_theme': True, 'auto_save': False, 'font_size': 12}
        }

    def save_settings_to_file(self):
        settings_file = "burp_clone_settings.json"
        with open(settings_file, 'w') as f:
            json.dump(self.settings, f, indent=2)

    def setup_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        self.proxy_status_label = QLabel("🔴 Proxy: Stopped")
        toolbar.addWidget(self.proxy_status_label)

        toolbar.addSeparator()

        start_proxy_action = QAction(QIcon("▶"), "Start Proxy", self)
        start_proxy_action.triggered.connect(self.start_proxy)
        toolbar.addAction(start_proxy_action)

        stop_proxy_action = QAction(QIcon("⏹"), "Stop Proxy", self)
        stop_proxy_action.triggered.connect(self.stop_proxy)
        toolbar.addAction(stop_proxy_action)

        toolbar.addSeparator()

        scan_action = QAction(QIcon("🔍"), "Quick Scan", self)
        scan_action.triggered.connect(lambda: self.tabs.setCurrentWidget(self.scanner_tab))
        toolbar.addAction(scan_action)

        spider_action = QAction(QIcon("🕷️"), "Spider", self)
        spider_action.triggered.connect(lambda: self.tabs.setCurrentWidget(self.spider_tab))
        toolbar.addAction(spider_action)

        toolbar.addSeparator()

        settings_action = QAction(QIcon("⚙️"), "Settings", self)
        settings_action.triggered.connect(self.show_settings)
        toolbar.addAction(settings_action)

        toolbar.addWidget(QLabel(""))

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("🔍 Quick search (Ctrl+K)")
        self.search_bar.setMaximumWidth(300)
        self.search_bar.textChanged.connect(self.quick_search)
        toolbar.addWidget(self.search_bar)

    def setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+Shift+P"), self, self.start_proxy)
        QShortcut(QKeySequence("Ctrl+Shift+S"), self, self.stop_proxy)
        QShortcut(QKeySequence("Ctrl+K"), self, self.focus_search)
        QShortcut(QKeySequence("Ctrl+R"), self, self.run_scan_shortcut)
        QShortcut(QKeySequence("Ctrl+H"), self, lambda: self.tabs.setCurrentWidget(self.proxy_tab))
        QShortcut(QKeySequence("Ctrl+I"), self, lambda: self.tabs.setCurrentWidget(self.scanner_tab))
        QShortcut(QKeySequence("Ctrl+T"), self, lambda: self.tabs.setCurrentWidget(self.target_tab))
        QShortcut(QKeySequence("Ctrl+D"), self, lambda: self.tabs.setCurrentWidget(self.decoder_tab))
        QShortcut(QKeySequence("Ctrl+,", self, self.show_settings))

    def focus_search(self):
        self.search_bar.setFocus()
        self.search_bar.selectAll()

    def run_scan_shortcut(self):
        self.tabs.setCurrentWidget(self.scanner_tab)
        if hasattr(self, 'scanner_tab'):
            if self.scanner_tab.url_input.text():
                self.scanner_tab.start_scan()

    def quick_search(self, text):
        if not text:
            return
        text_lower = text.lower()

        if hasattr(self, 'proxy_tab') and self.proxy_tab.history_table.rowCount() > 0:
            for row in range(self.proxy_tab.history_table.rowCount()):
                for col in range(3):
                    item = self.proxy_tab.history_table.item(row, col)
                    if item and text_lower in item.text().lower():
                        self.proxy_tab.history_table.selectRow(row)
                        self.tabs.setCurrentWidget(self.proxy_tab)
                        return

        self.statusBar().showMessage(f"Search: {text} (no results)")

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
        file_menu.addAction("Save Project", self.save_project)
        file_menu.addSeparator()
        file_menu.addAction("Settings", self.show_settings)
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close)

        proxy_menu = menubar.addMenu("Proxy")
        proxy_menu.addAction("Start Proxy", self.start_proxy)
        proxy_menu.addAction("Stop Proxy", self.stop_proxy)
        proxy_menu.addSeparator()
        proxy_menu.addAction("Toggle Intercept", self.toggle_intercept)
        proxy_menu.addAction("Toggle Passive Scan", self.toggle_passive_scan)

        scan_menu = menubar.addMenu("Scan")
        scan_menu.addAction("Run Active Scan", lambda: self.tabs.setCurrentWidget(self.scanner_tab))
        scan_menu.addAction("Run Spider", lambda: self.tabs.setCurrentWidget(self.spider_tab))

        tools_menu = menubar.addMenu("Tools")
        tools_menu.addAction("Repeater", lambda: self.tabs.setCurrentWidget(self.repeater_tab))
        tools_menu.addAction("Intruder", lambda: self.tabs.setCurrentWidget(self.intruder_tab))
        tools_menu.addAction("Decoder", lambda: self.tabs.setCurrentWidget(self.decoder_tab))

        view_menu = menubar.addMenu("View")
        view_menu.addAction("Proxy History", lambda: self.tabs.setCurrentWidget(self.proxy_tab))
        view_menu.addAction("Target Scope", lambda: self.tabs.setCurrentWidget(self.target_tab))

        help_menu = menubar.addMenu("Help")
        help_menu.addAction("Keyboard Shortcuts", self.show_shortcuts)
        help_menu.addAction("About", self.show_about)

    def new_project(self):
        self.target_manager = TargetManager()
        self.scan_results = []
        if hasattr(self, 'spider_tab'):
            self.spider_tab.results_table.setRowCount(0)
        if hasattr(self, 'scanner_tab'):
            self.scanner_tab.results_table.setRowCount(0)
        self.statusBar().showMessage("New project created")

    def open_project(self):
        file, _ = QFileDialog.getOpenFileName(self, "Open Project", "", "Burp Clone Project (*.bcp)")
        if file:
            QMessageBox.information(self, "Open Project", f"Opening: {file}")

    def save_project(self):
        file, _ = QFileDialog.getSaveFileName(self, "Save Project", "", "Burp Clone Project (*.bcp)")
        if file:
            QMessageBox.information(self, "Save Project", f"Saving: {file}")

    def show_settings(self):
        dialog = SettingsDialog(self)
        dialog.load_settings(self.settings)
        if dialog.exec():
            self.settings = dialog.get_settings()
            self.save_settings_to_file()
            self.statusBar().showMessage("Settings saved")

    def show_shortcuts(self):
        shortcuts = """
        <h2>Keyboard Shortcuts</h2>
        <table>
        <tr><td><b>Ctrl+Shift+P</b></td><td>Start Proxy</td></tr>
        <tr><td><b>Ctrl+Shift+S</b></td><td>Stop Proxy</td></tr>
        <tr><td><b>Ctrl+K</b></td><td>Quick Search</td></tr>
        <tr><td><b>Ctrl+R</b></td><td>Run Scan</td></tr>
        <tr><td><b>Ctrl+H</b></td><td>Proxy Tab</td></tr>
        <tr><td><b>Ctrl+I</b></td><td>Scanner Tab</td></tr>
        <tr><td><b>Ctrl+T</b></td><td>Target Tab</td></tr>
        <tr><td><b>Ctrl+D</b></td><td>Decoder Tab</td></tr>
        <tr><td><b>Ctrl+,</b></td><td>Settings</td></tr>
        </table>
        """
        QMessageBox.about(self, "Keyboard Shortcuts", shortcuts)

    def start_proxy(self):
        if not self.proxy_server:
            host = self.settings['proxy']['host']
            port = self.settings['proxy']['port']
            self.proxy_server = HTTPSProxy(host, port, "proxy_history.db")
            self.proxy_thread = threading.Thread(target=self.proxy_server.start)
            self.proxy_thread.daemon = True
            self.proxy_thread.start()
            self.proxy_status_label.setText(f"🟢 Proxy: Running on {host}:{port}")
            self.statusBar().showMessage(f"Proxy started on {host}:{port}")
            time.sleep(1)

    def stop_proxy(self):
        if self.proxy_server:
            self.proxy_server.stop()
            self.proxy_server = None
            self.proxy_status_label.setText("🔴 Proxy: Stopped")
            self.statusBar().showMessage("Proxy stopped")

    def toggle_intercept(self):
        if self.proxy_server:
            current = self.proxy_server.intercept_mode
            self.proxy_server.set_intercept_mode(not current)
            self.statusBar().showMessage(f"Intercept: {'ON' if not current else 'OFF'}")

    def toggle_passive_scan(self):
        if hasattr(self, 'passive_scanner'):
            current = self.passive_scanner.enabled
            self.passive_scanner.enabled = not current
            self.statusBar().showMessage(f"Passive Scanner: {'ON' if not current else 'OFF'}")

    def show_about(self):
        QMessageBox.about(self, "About Burp Clone",
                         "Burp Clone v1.0\n\nWeb Application Penetration Testing Toolkit\n\nBuilt with Python and PyQt6\n\n🚀 Professional Security Tool")


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

        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶ Start")
        self.start_btn.clicked.connect(self.start_proxy)
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.clicked.connect(self.stop_proxy)
        self.intercept_btn = QPushButton("🔄 Intercept")
        self.intercept_btn.setCheckable(True)
        self.passive_btn = QPushButton("👁 Passive")
        self.passive_btn.setCheckable(True)
        self.passive_btn.clicked.connect(self.toggle_passive)
        self.clear_btn = QPushButton("Clear")

        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.intercept_btn)
        button_layout.addWidget(self.passive_btn)
        button_layout.addWidget(self.clear_btn)
        left_layout.addLayout(button_layout)

        left_layout.addWidget(QLabel("Request History"))
        left_layout.addWidget(self.history_table)

        layout.addWidget(left_panel, 1)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        right_layout.addWidget(QLabel("Request Details"))
        self.request_detail = QTextEdit()
        self.request_detail.setReadOnly(True)
        right_layout.addWidget(self.request_detail)

        right_layout.addWidget(QLabel("Response Details"))
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

    def toggle_passive(self, checked):
        self.parent.toggle_passive_scan()

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
        top_layout.addWidget(QLabel("🌐"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://example.com")
        top_layout.addWidget(self.url_input, 1)
        self.start_btn = QPushButton("▶ Start")
        self.start_btn.clicked.connect(self.start_spider)
        top_layout.addWidget(self.start_btn)
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.clicked.connect(self.stop_spider)
        self.stop_btn.setEnabled(False)
        top_layout.addWidget(self.stop_btn)
        layout.addLayout(top_layout)

        options_layout = QHBoxLayout()
        options_layout.addWidget(QLabel("Max:"))
        self.max_pages = QSpinBox()
        self.max_pages.setValue(100)
        options_layout.addWidget(self.max_pages)
        options_layout.addWidget(QLabel("pages"))
        options_layout.addSpacing(20)
        options_layout.addWidget(QLabel("Depth:"))
        self.max_depth = QSpinBox()
        self.max_depth.setValue(3)
        options_layout.addWidget(self.max_depth)
        options_layout.addStretch()
        layout.addLayout(options_layout)

        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["URL", "Status", "Title", "Links"])
        layout.addWidget(self.results_table)

    def start_spider(self):
        url = self.url_input.text()
        if not url:
            return

        config = CrawlConfig(max_pages=self.max_pages.value(), max_depth=self.max_depth.value())
        self.spider = Spider(url, config)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        thread = threading.Thread(target=self.run_spider)
        thread.start()

    def run_spider(self):
        def progress(current, queue, url):
            self.progress.setValue(current)

        results = self.spider.crawl(progress)
        self.results_table.setRowCount(len(results))
        for i, result in enumerate(results):
            self.results_table.setItem(i, 0, QTableWidgetItem(result.url))
            self.results_table.setItem(i, 1, QTableWidgetItem(str(result.status_code)))
            self.results_table.setItem(i, 2, QTableWidgetItem(result.title or ""))
            self.results_table.setItem(i, 3, QTableWidgetItem(str(len(result.links))))

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def stop_spider(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)


class ScannerTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.scanner_engine = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        top_layout = QHBoxLayout()
        top_layout.addWidget(QLabel("🔍"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://example.com/page?id=1")
        top_layout.addWidget(self.url_input, 1)
        self.scan_btn = QPushButton("▶ Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        top_layout.addWidget(self.scan_btn)
        layout.addLayout(top_layout)

        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(["#", "Issue", "Severity", "URL", "Parameter", "Confidence"])
        layout.addWidget(self.results_table)

        btn_layout = QHBoxLayout()
        self.report_btn = QPushButton("📄 Generate Report")
        self.report_btn.clicked.connect(self.generate_report)
        btn_layout.addWidget(self.report_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

    def start_scan(self):
        url = self.url_input.text()
        if not url:
            return

        self.scan_btn.setEnabled(False)
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
            self.results_table.setItem(i, 3, QTableWidgetItem(issue.url[:50]))
            self.results_table.setItem(i, 4, QTableWidgetItem(issue.parameter or ""))
            self.results_table.setItem(i, 5, QTableWidgetItem(issue.confidence))

        self.progress.setValue(100)
        self.scan_btn.setEnabled(True)

    def generate_report(self):
        if self.scanner_engine:
            generator = ReportGenerator()
            generator.set_target("Scan Report", self.url_input.text())
            generator.add_issues(self.scanner_engine.issue_tracker.issues)
            generator.generate_html("security_report.html")
            QMessageBox.information(self, "Report", "Report saved to security_report.html")


class IntruderTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("📝 Request (use §param§ for payload)"))
        self.request_input = QTextEdit()
        self.request_input.setPlaceholderText("GET /path§param§ HTTP/1.1\nHost: example.com")
        layout.addWidget(self.request_input)

        opts = QHBoxLayout()
        opts.addWidget(QLabel("Mode:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Sniper", "Battering Ram", "Pitchfork", "Cluster Bomb"])
        opts.addWidget(self.mode_combo)
        opts.addWidget(QLabel("Payloads:"))
        self.payloads = QTextEdit()
        self.payloads.setMaximumHeight(50)
        self.payloads.setPlaceholderText("one per line")
        opts.addWidget(self.payloads, 1)
        layout.addLayout(opts)

        self.attack_btn = QPushButton("💥 Start Attack")
        self.attack_btn.clicked.connect(self.start_attack)
        layout.addWidget(self.attack_btn)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["#", "Payload", "Status", "Length", "Time"])
        layout.addWidget(self.results_table)

    def start_attack(self):
        req = self.request_input.toPlainText()
        payloads = [p for p in self.payloads.toPlainText().split('\n') if p.strip()]

        if not req or not payloads:
            return

        self.intruder = Intruder()
        self.intruder.set_request(req)
        for payload in payloads:
            self.intruder.set_payloads('param', payloads)

        mode = AttackMode[self.mode_combo.currentText().replace(' ', '_').upper()]
        self.intruder.set_attack_mode(mode)

        results = self.intruder.execute()
        self.results_table.setRowCount(len(results))
        for i, r in enumerate(results):
            self.results_table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
            self.results_table.setItem(i, 1, QTableWidgetItem(r.payload[:20]))
            self.results_table.setItem(i, 2, QTableWidgetItem(str(r.status_code)))
            self.results_table.setItem(i, 3, QTableWidgetItem(str(r.response_length)))
            self.results_table.setItem(i, 4, QTableWidgetItem(str(r.response_time_ms)))


class RepeaterTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        layout = QHBoxLayout(self)

        left = QVBoxLayout()
        left.addWidget(QLabel("📤 Request"))
        req_layout = QHBoxLayout()
        self.method = QComboBox()
        self.method.addItems(["GET", "POST", "PUT", "DELETE"])
        req_layout.addWidget(self.method)
        self.url = QLineEdit()
        self.url.setPlaceholderText("http://example.com/api")
        req_layout.addWidget(self.url, 1)
        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send)
        req_layout.addWidget(self.send_btn)
        left.addLayout(req_layout)
        self.request_body = QTextEdit()
        left.addWidget(self.request_body)
        layout.addWidget(left, 1)

        right = QVBoxLayout()
        right.addWidget(QLabel("📥 Response"))
        self.response = QTextEdit()
        self.response.setReadOnly(True)
        right.addWidget(self.response)
        layout.addWidget(right, 1)

    def send(self):
        method = self.method.currentText()
        url = self.url.text()
        if not url:
            return

        self.send_btn.setEnabled(False)
        thread = threading.Thread(target=self.do_send, args=(method, url))
        thread.start()

    def do_send(self, method, url):
        req = RepeaterRequest(0, f"{method} {url[:30]}", method, url, {}, self.request_body.toPlainText().encode())
        resp, status, headers, time_ms = self.parent.repeater.send(req)
        self.response.setPlainText(f"Status: {status} | Time: {time_ms}ms\n\n{resp.decode('utf-8', errors='replace')[:3000]}")
        self.send_btn.setEnabled(True)


class DecoderTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.input = QTextEdit()
        self.input.setPlaceholderText("Enter text...")
        layout.addWidget(self.input)

        btns = QHBoxLayout()
        btns.addWidget(QPushButton("🔓 Decode")).clicked.connect(lambda: self.decode(False))
        btns.addWidget(QPushButton("🔒 Encode")).clicked.connect(lambda: self.decode(True))
        btns.addWidget(QPushButton("🔑 Hash")).clicked.connect(self.hash)
        btns.addStretch()
        layout.addLayout(btns)

        self.type_combo = QComboBox()
        self.type_combo.addItems(["Base64", "URL", "Hex", "MD5", "SHA256"])
        btns.addWidget(self.type_combo)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

    def decode(self, encode):
        data = self.input.toPlainText()
        enc = self.type_combo.currentText().lower()
        if enc in ['md5', 'sha256']:
            self.output.setPlainText("Hash cannot be decoded")
            return
        if encode:
            r, _ = self.parent.utils.encode(data, enc)
        else:
            r, _ = self.parent.utils.decode(data, enc)
        self.output.setPlainText(r)

    def hash(self):
        data = self.input.toPlainText()
        enc = self.type_combo.currentText().lower()
        if enc in ['md5', 'sha256']:
            self.output.setPlainText(self.parent.utils.hash(data, enc))


class TargetTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("🎯 Scope"))
        inc = QHBoxLayout()
        inc.addWidget(QLabel("Include:"))
        self.include = QLineEdit()
        self.include.setPlaceholderText(".*example.com.*")
        inc.addWidget(self.include, 1)
        inc.addWidget(QPushButton("+").clicked(lambda: self.add_scope(True)))
        layout.addLayout(inc)

        exc = QHBoxLayout()
        exc.addWidget(QLabel("Exclude:"))
        self.exclude = QLineEdit()
        self.exclude.setPlaceholderText(".*logout.*")
        exc.addWidget(self.exclude, 1)
        exc.addWidget(QPushButton("+").clicked(lambda: self.add_scope(False)))
        layout.addLayout(exc)

        layout.addWidget(QLabel("📊 Site Map"))
        self.sitemap = QTableWidget()
        self.sitemap.setColumnCount(4)
        self.sitemap.setHorizontalHeaderLabels(["Host", "URL", "Status", "Issues"])
        layout.addWidget(self.sitemap)

    def add_scope(self, include):
        pattern = self.include.text() if include else self.exclude.text()
        if pattern:
            if include:
                self.parent.target_manager.add_target(pattern)
            else:
                self.parent.target_manager.add_exclusion(pattern)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
    app.setPalette(palette)

    window = BurpCloneGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()