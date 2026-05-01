# Burp Clone

A web application penetration testing toolkit built in Python.

## Features

### Core Tools
- **HTTP/HTTPS Proxy** - Intercept and modify web traffic
- **Request/Response Viewer** - Raw, parsed, and hex views
- **Spider/Crawler** - Discover URLs, forms, and site structure
- **Vulnerability Scanner** - Detect XSS, SQLi, SSRF, XXE, IDOR
- **Intruder** - Fuzz and brute-force with multiple attack modes
- **Repeater** - Manual request testing with history
- **Utilities** - Decoder, Encoder, Hash Generator, Comparator

### Capabilities
- SSL/TLS interception with self-signed certificates
- Request filtering (blacklist/whitelist)
- Proxy chaining (upstream proxy support)
- Session handling and authentication
- Crawl pause/resume
- 4 attack modes (Sniper, Battering Ram, Pitchfork, Cluster Bomb)

## Installation

```bash
# Clone the repository
git clone https://github.com/zelalemtsegaye2003-droid/burp-suite-clone.git
cd burp-suite-clone

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Interactive CLI
```bash
python -m src.main_cli --cli
```

### Proxy Server
```bash
python -m src.main_cli --proxy --port 8080
```

### Vulnerability Scanner
```bash
python -m src.main_cli --scan http://target.com
```

### Spider
```bash
python -m src.main_cli --spider http://target.com --max-pages 100
```

### Repeater
```bash
python -m src.main_cli --repeater GET http://example.com/api
```

### Utilities
```bash
# Decode
python -m src.main_cli --decode "SGVsbG8gV29ybGQ=" base64

# Encode
python -m src.main_cli --encode "Hello World" base64

# Hash
python -m src.main_cli --hash "password123" md5
```

## Module Structure

```
src/
├── proxy/           # HTTP/HTTPS proxy server
│   ├── server.py       # Basic proxy
│   ├── https_proxy.py  # HTTPS with SSL interception
│   ├── database.py     # SQLite logging
│   ├── ssl_cert.py     # Certificate generation
│   ├── filter.py       # Blacklist/whitelist
│   ├── chaining.py     # Upstream proxy
│   └── interceptor.py  # Intercept mode
├── core/            # Core functionality
│   ├── models.py       # HTTP message models
│   └── replay.py       # Request replay
├── ui/              # User interface
│   ├── cli.py          # Interactive CLI
│   ├── history.py      # Traffic history
│   ├── raw_view.py     # Raw view
│   ├── parsed_view.py  # Parsed view
│   ├── hex_view.py     # Hex view
│   ├── editor.py       # Request editor
│   └── formats.py      # Format detection
├── spider/          # Web crawler
│   ├── crawler.py      # Core spider
│   ├── robots.py       # robots.txt parser
│   ├── advanced.py     # Forms, sitemap
│   └── session.py      # Session handling
├── scanner/         # Vulnerability detection
│   ├── scanner.py      # Scanner framework
│   └── checks.py       # Vulnerability checks
├── intruder/        # Fuzzer
│   └── intruder.py     # Attack engine
├── repeater/        # Manual testing
│   └── repeater.py    # Request tool
└── utils/           # Utilities
    └── codec.py        # Decoder/Encoder/Hash
```

## Requirements

- Python 3.8+
- requests
- httpx
- beautifulsoup4
- lxml
- cryptography

## License

MIT License

## Disclaimer

This tool is for educational and authorized security testing purposes only.