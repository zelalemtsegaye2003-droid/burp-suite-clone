"""Main entry point for Burp Clone"""
import sys


def main():
    print("Burp Clone v0.1.0")
    print("=" * 40)
    print("Starting...")
    print("\nAvailable modules:")
    print("  - proxy: HTTP proxy server")
    print("  - scanner: Vulnerability detection")
    print("  - spider: Web crawler")
    print("  - intruder: Fuzzing tool")
    print("  - repeater: Manual testing")
    print("\nRun with: python -m src.<module>")
    return 0


if __name__ == "__main__":
    sys.exit(main())