# Burp Clone

A web application penetration testing toolkit built in Python.

## Features

- HTTP Proxy with interception
- Request/Response viewer
- Web spider/crawler
- Vulnerability scanner
- Intruder (fuzzer)
- Repeater

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python -m src.main
```

## Project Structure

```
src/
  proxy/      - HTTP proxy server
  core/       - Core engine
  ui/         - GUI interface
  scanner/    - Vulnerability detection
  spider/     - Web crawler
  intruder/   - Fuzzing tool
  repeater/   - Manual testing
  utils/      - Utilities
```