"""Utilities - Decoder, Encoder, Hash, Comparator"""
import base64
import urllib.parse
import hashlib
import binascii
from typing import Optional, Dict, Tuple
import json


class Decoder:
    SUPPORTED_TYPES = ['base64', 'url', 'hex', 'html', 'unicode']

    @staticmethod
    def decode_base64(data: str, url_safe: bool = False) -> Tuple[str, bool]:
        try:
            if url_safe:
                decoded = base64.urlsafe_b64decode(data.encode()).decode('utf-8', errors='replace')
            else:
                decoded = base64.b64decode(data.encode()).decode('utf-8', errors='replace')
            return decoded, True
        except Exception as e:
            return str(e), False

    @staticmethod
    def decode_url(data: str) -> Tuple[str, bool]:
        try:
            decoded = urllib.parse.unquote(data)
            return decoded, True
        except Exception as e:
            return str(e), False

    @staticmethod
    def decode_hex(data: str) -> Tuple[str, bool]:
        try:
            cleaned = data.replace(' ', '').replace('0x', '')
            decoded = binascii.unhexlify(cleaned).decode('utf-8', errors='replace')
            return decoded, True
        except Exception as e:
            return str(e), False

    @staticmethod
    def decode_html(data: str) -> Tuple[str, bool]:
        try:
            import html
            decoded = html.unescape(data)
            return decoded, True
        except Exception as e:
            return str(e), False

    @staticmethod
    def decode_unicode(data: str) -> Tuple[str, bool]:
        try:
            decoded = data.encode('utf-8').decode('unicode_escape')
            return decoded, True
        except Exception as e:
            return str(e), False

    @staticmethod
    def auto_decode(data: str) -> Dict[str, str]:
        results = {}

        for encoding in Decoder.SUPPORTED_TYPES:
            if encoding == 'base64':
                decoded, success = Decoder.decode_base64(data)
            elif encoding == 'url':
                decoded, success = Decoder.decode_url(data)
            elif encoding == 'hex':
                decoded, success = Decoder.decode_hex(data)
            elif encoding == 'html':
                decoded, success = Decoder.decode_html(data)
            elif encoding == 'unicode':
                decoded, success = Decoder.decode_unicode(data)
            else:
                continue

            results[encoding] = decoded if success else f"Error: {decoded}"

        return results


class Encoder:
    SUPPORTED_TYPES = ['base64', 'url', 'hex', 'html', 'unicode']

    @staticmethod
    def encode_base64(data: str, url_safe: bool = False) -> Tuple[str, bool]:
        try:
            if url_safe:
                encoded = base64.urlsafe_b64encode(data.encode()).decode()
            else:
                encoded = base64.b64encode(data.encode()).decode()
            return encoded, True
        except Exception as e:
            return str(e), False

    @staticmethod
    def encode_url(data: str, full: bool = False) -> Tuple[str, bool]:
        try:
            if full:
                encoded = urllib.parse.quote_plus(data)
            else:
                encoded = urllib.parse.quote(data)
            return encoded, True
        except Exception as e:
            return str(e), False

    @staticmethod
    def encode_hex(data: str, uppercase: bool = False) -> Tuple[str, bool]:
        try:
            encoded = binascii.hexlify(data.encode()).decode()
            if uppercase:
                encoded = encoded.upper()
            return encoded, True
        except Exception as e:
            return str(e), False

    @staticmethod
    def encode_html(data: str) -> Tuple[str, bool]:
        try:
            import html
            encoded = html.escape(data)
            return encoded, True
        except Exception as e:
            return str(e), False

    @staticmethod
    def encode_unicode(data: str) -> Tuple[str, bool]:
        try:
            encoded = data.encode('unicode_escape').decode()
            return encoded, True
        except Exception as e:
            return str(e), False


class HashGenerator:
    ALGORITHMS = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3_256', 'blake2b']

    @staticmethod
    def hash_md5(data: str) -> str:
        return hashlib.md5(data.encode()).hexdigest()

    @staticmethod
    def hash_sha1(data: str) -> str:
        return hashlib.sha1(data.encode()).hexdigest()

    @staticmethod
    def hash_sha256(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def hash_sha512(data: str) -> str:
        return hashlib.sha512(data.encode()).hexdigest()

    @staticmethod
    def hash_all(data: str) -> Dict[str, str]:
        return {
            'MD5': HashGenerator.hash_md5(data),
            'SHA1': HashGenerator.hash_sha1(data),
            'SHA256': HashGenerator.hash_sha256(data),
            'SHA512': HashGenerator.hash_sha512(data),
            'SHA3-256': hashlib.sha3_256(data.encode()).hexdigest(),
            'BLAKE2b': hashlib.blake2b(data.encode()).hexdigest()
        }

    @staticmethod
    def verify_hash(data: str, hash_value: str, algorithm: str = 'md5') -> bool:
        if algorithm.lower() == 'md5':
            return HashGenerator.hash_md5(data) == hash_value.lower()
        elif algorithm.lower() == 'sha1':
            return HashGenerator.hash_sha1(data) == hash_value.lower()
        elif algorithm.lower() in ['sha256', 'sha-256']:
            return HashGenerator.hash_sha256(data) == hash_value.lower()
        elif algorithm.lower() in ['sha512', 'sha-512']:
            return HashGenerator.hash_sha512(data) == hash_value.lower()
        return False


class Comparator:
    @staticmethod
    def compare_text(text1: str, text2: str, ignore_case: bool = False, ignore_spaces: bool = False) -> Dict:
        if ignore_case:
            text1 = text1.lower()
            text2 = text2.lower()

        if ignore_spaces:
            text1 = text1.replace(' ', '').replace('\n', '').replace('\t', '')
            text2 = text2.replace(' ', '').replace('\n', '').replace('\t', '')

        identical = text1 == text2

        diff = {
            'identical': identical,
            'length1': len(text1),
            'length2': len(text2),
            'char_diff': abs(len(text1) - len(text2)),
            'lines_diff': abs(text1.count('\n') - text2.count('\n'))
        }

        if not identical:
            diff['differences'] = Comparator._find_differences(text1, text2)

        return diff

    @staticmethod
    def _find_differences(text1: str, text2: str) -> list:
        differences = []

        lines1 = text1.split('\n')
        lines2 = text2.split('\n')

        max_lines = max(len(lines1), len(lines2))

        for i in range(max_lines):
            line1 = lines1[i] if i < len(lines1) else None
            line2 = lines2[i] if i < len(lines2) else None

            if line1 != line2:
                differences.append({
                    'line': i + 1,
                    'text1': line1[:50] if line1 else '<missing>',
                    'text2': line2[:50] if line2 else '<missing>'
                })

        return differences

    @staticmethod
    def compare_bytes(data1: bytes, data2: bytes) -> Dict:
        return {
            'identical': data1 == data2,
            'size1': len(data1),
            'size2': len(data2),
            'difference': abs(len(data1) - len(data2))
        }


class UtilitiesSuite:
    def __init__(self):
        self.decoder = Decoder()
        self.encoder = Encoder()
        self.hasher = HashGenerator()
        self.comparator = Comparator()

    def decode(self, data: str, encoding: str) -> Tuple[str, bool]:
        if encoding.lower() == 'base64':
            return Decoder.decode_base64(data)
        elif encoding.lower() == 'url':
            return Decoder.decode_url(data)
        elif encoding.lower() == 'hex':
            return Decoder.decode_hex(data)
        elif encoding.lower() == 'html':
            return Decoder.decode_html(data)
        elif encoding.lower() == 'unicode':
            return Decoder.decode_unicode(data)
        return f"Unknown encoding: {encoding}", False

    def encode(self, data: str, encoding: str) -> Tuple[str, bool]:
        if encoding.lower() == 'base64':
            return Encoder.encode_base64(data)
        elif encoding.lower() == 'url':
            return Encoder.encode_url(data)
        elif encoding.lower() == 'hex':
            return Encoder.encode_hex(data)
        elif encoding.lower() == 'html':
            return Encoder.encode_html(data)
        elif encoding.lower() == 'unicode':
            return Encoder.encode_unicode(data)
        return f"Unknown encoding: {encoding}", False

    def hash(self, data: str, algorithm: str = 'md5') -> str:
        if algorithm.lower() == 'md5':
            return HashGenerator.hash_md5(data)
        elif algorithm.lower() in ['sha1', 'sha-1']:
            return HashGenerator.hash_sha1(data)
        elif algorithm.lower() in ['sha256', 'sha-256']:
            return HashGenerator.hash_sha256(data)
        elif algorithm.lower() in ['sha512', 'sha-512']:
            return HashGenerator.hash_sha512(data)
        return "Unknown algorithm"

    def hash_all(self, data: str) -> Dict[str, str]:
        return HashGenerator.hash_all(data)

    def compare(self, data1: str, data2: str) -> Dict:
        return Comparator.compare_text(data1, data2)


if __name__ == '__main__':
    suite = UtilitiesSuite()

    print("=== Decoder ===")
    result, success = suite.decode("SGVsbG8gV29ybGQ=", "base64")
    print(f"Base64 decode: {result}")

    print("\n=== Encoder ===")
    result, success = suite.encode("Hello World", "base64")
    print(f"Base64 encode: {result}")

    print("\n=== Hash ===")
    hashes = suite.hash_all("password123")
    for alg, h in hashes.items():
        print(f"{alg}: {h}")

    print("\n=== Comparator ===")
    diff = suite.compare("Hello World", "Hello World!")
    print(f"Identical: {diff['identical']}")