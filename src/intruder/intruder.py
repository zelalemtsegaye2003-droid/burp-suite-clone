"""Intruder - Fuzzer and Brute-forcer"""
from typing import List, Dict, Optional, Callable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from itertools import product, cycle
import re
import time
import requests
import socket
import ssl


class AttackMode(Enum):
    SNIPER = "sniper"
    BATTERING_RAM = "battering_ram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "cluster_bomb"


class PayloadType(Enum):
    SIMPLE_LIST = "simple_list"
    BRUTE_FORCE = "brute_force"
    NUMBERS = "numbers"
    DATES = "dates"
    HEX = "hex"
    CUSTOM = "custom"


@dataclass
class PayloadPosition:
    name: str
    start_marker: str
    end_marker: str
    original_value: str = ""


@dataclass
class IntruderRequest:
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    positions: List[PayloadPosition]


@dataclass
class IntruderResult:
    request_num: int
    position: str
    payload: str
    status_code: int
    response_length: int
    response_time_ms: int
    matched: bool = False
    error: Optional[str] = None


class PayloadGenerator:
    def __init__(self):
        pass

    def generate_simple_list(self, items: List[str]) -> Iterator[str]:
        for item in items:
            yield item

    def generate_numbers(self, start: int, end: int, step: int = 1) -> Iterator[str]:
        num = start
        while num <= end:
            yield str(num)
            num += step

    def generate_brute_force(self, charset: str, min_length: int, max_length: int) -> Iterator[str]:
        from itertools import product

        for length in range(min_length, max_length + 1):
            for combo in product(charset, repeat=length):
                yield ''.join(combo)

    def generate_dates(self, start_date: str, end_date: str, format: str = "%Y-%m-%d") -> Iterator[str]:
        from datetime import datetime, timedelta

        try:
            start = datetime.strptime(start_date, format)
            end = datetime.strptime(end_date, format)

            current = start
            while current <= end:
                yield current.strftime(format)
                current += timedelta(days=1)
        except:
            yield start_date

    def generate_hex(self, start: int, end: int) -> Iterator[str]:
        num = start
        while num <= end:
            yield hex(num)
            num += 1


class IntruderEngine:
    def __init__(self, request: IntruderRequest):
        self.request = request
        self.payload_generators: Dict[str, PayloadGenerator] = {}
        self.payloads: Dict[str, List[str]] = {}
        self.results: List[IntruderResult] = []
        self.mode = AttackMode.SNIPER
        self.match_patterns: List[str] = []
        self.timeout = 30

    def set_payloads(self, position_name: str, payloads: List[str]):
        self.payloads[position_name] = payloads

    def set_payload_generator(self, position_name: str, gen: PayloadGenerator):
        self.payload_generators[position_name] = gen

    def set_attack_mode(self, mode: AttackMode):
        self.mode = mode

    def add_match_pattern(self, pattern: str):
        self.match_patterns.append(pattern)

    def execute(self, progress_callback: Callable[[int, int, str], None] = None) -> List[IntruderResult]:
        self.results = []

        if self.mode == AttackMode.SNIPER:
            return self._attack_sniper(progress_callback)
        elif self.mode == AttackMode.BATTERING_RAM:
            return self._attack_battering_ram(progress_callback)
        elif self.mode == AttackMode.PITCHFORK:
            return self._attack_pitchfork(progress_callback)
        elif self.mode == AttackMode.CLUSTER_BOMB:
            return self._attack_cluster_bomb(progress_callback)

        return self.results

    def _attack_sniper(self, callback: Callable = None) -> List[IntruderResult]:
        request_num = 0

        for pos in self.request.positions:
            payloads = self.payloads.get(pos.name, [])

            for payload in payloads:
                request_num += 1

                modified_request = self._apply_payload(pos, payload)
                result = self._send_request(modified_request, pos.name, payload, request_num)
                self.results.append(result)

                if callback:
                    callback(request_num, len(payloads), payload)

        return self.results

    def _attack_battering_ram(self, callback: Callable = None) -> List[IntruderResult]:
        request_num = 0

        all_payloads = list(self.payloads.values())
        if not all_payloads:
            return self.results

        max_len = max(len(p) for p in all_payloads)

        for i in range(max_len):
            request_num += 1
            payload_map = {}

            for pos in self.request.positions:
                payloads = self.payloads.get(pos.name, [])
                if payloads:
                    payload = payloads[i % len(payloads)]
                    payload_map[pos.name] = payload

            modified_request = self._apply_payloads(payload_map)
            result = self._send_request(modified_request, "", payload_map.get(list(self.payloads.keys())[0], [""])[0], request_num)
            self.results.append(result)

            if callback:
                callback(request_num, max_len, str(payload_map))

        return self.results

    def _attack_pitchfork(self, callback: Callable = None) -> List[IntruderResult]:
        request_num = 0

        min_len = min(len(p) for p in self.payloads.values()) if self.payloads else 0

        for i in range(min_len):
            request_num += 1
            payload_map = {}

            for pos in self.request.positions:
                payloads = self.payloads.get(pos.name, [])
                if payloads and i < len(payloads):
                    payload_map[pos.name] = payloads[i]

            modified_request = self._apply_payloads(payload_map)
            result = self._send_request(modified_request, "", str(i), request_num)
            self.results.append(result)

            if callback:
                callback(request_num, min_len, str(payload_map))

        return self.results

    def _attack_cluster_bomb(self, callback: Callable = None) -> List[IntruderResult]:
        request_num = 0

        payload_lists = [self.payloads.get(pos.name, []) for pos in self.request.positions]

        for combo in product(*payload_lists):
            request_num += 1

            payload_map = {}
            for i, pos in enumerate(self.request.positions):
                payload_map[pos.name] = combo[i]

            modified_request = self._apply_payloads(payload_map)
            result = self._send_request(modified_request, "", str(combo), request_num)
            self.results.append(result)

            total = 1
            for pl in payload_lists:
                total *= len(pl) if pl else 1

            if callback:
                callback(request_num, total, str(combo))

        return self.results

    def _apply_payload(self, position: PayloadPosition, payload: str) -> Dict:
        return {
            'method': self.request.method,
            'url': self.request.url.replace(
                f"{position.start_marker}{position.original_value}{position.end_marker}",
                f"{position.start_marker}{payload}{position.end_marker}"
            ),
            'headers': self.request.headers.copy(),
            'body': self.request.body.replace(
                f"{position.start_marker}{position.original_value}{position.end_marker}",
                f"{position.start_marker}{payload}{position.end_marker}"
            ) if self.request.body else None
        }

    def _apply_payloads(self, payload_map: Dict[str, str]) -> Dict:
        url = self.request.url
        body = self.request.body or ""

        for pos in self.request.positions:
            if pos.name in payload_map:
                payload = payload_map[pos.name]
                placeholder = f"{pos.start_marker}{pos.original_value}{pos.end_marker}"
                replacement = f"{pos.start_marker}{payload}{pos.end_marker}"
                url = url.replace(placeholder, replacement)
                body = body.replace(placeholder, replacement)

        return {
            'method': self.request.method,
            'url': url,
            'headers': self.request.headers.copy(),
            'body': body
        }

    def _send_request(self, req_data: Dict, position: str, payload: str, request_num: int) -> IntruderResult:
        start_time = time.time()

        try:
            if req_data['url'].startswith('https'):
                response = requests.request(
                    method=req_data['method'],
                    url=req_data['url'],
                    headers=req_data['headers'],
                    data=req_data['body'],
                    timeout=self.timeout,
                    verify=False
                )
            else:
                response = requests.request(
                    method=req_data['method'],
                    url=req_data['url'],
                    headers=req_data['headers'],
                    data=req_data['body'],
                    timeout=self.timeout,
                    verify=False
                )

            response_time = int((time.time() - start_time) * 1000)

            matched = False
            if self.match_patterns:
                for pattern in self.match_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        matched = True
                        break

            return IntruderResult(
                request_num=request_num,
                position=position,
                payload=payload[:100],
                status_code=response.status_code,
                response_length=len(response.content),
                response_time_ms=response_time,
                matched=matched
            )

        except Exception as e:
            return IntruderResult(
                request_num=request_num,
                position=position,
                payload=payload[:100],
                status_code=0,
                response_length=0,
                response_time_ms=0,
                error=str(e)
            )


class Intruder:
    def __init__(self):
        self.engine: Optional[IntruderEngine] = None

    def set_request(self, raw_request: str) -> bool:
        try:
            lines = raw_request.split('\n')

            request_line = lines[0].split()
            method = request_line[0]
            url = request_line[1] if len(request_line) > 1 else "/"

            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if not line.strip():
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            body = '\n'.join(lines[body_start:]) if body_start < len(lines) else None

            positions = self._find_positions(url, body)

            request = IntruderRequest(
                method=method,
                url=url,
                headers=headers,
                body=body,
                positions=positions
            )

            self.engine = IntruderEngine(request)
            return True

        except Exception as e:
            return False

    def _find_positions(self, url: str, body: Optional[str]) -> List[PayloadPosition]:
        positions = []

        pattern = r'§([^§]+)§'

        for match in re.finditer(pattern, url):
            pos = PayloadPosition(
                name=match.group(1),
                start_marker='§',
                end_marker='§',
                original_value=match.group(1)
            )
            positions.append(pos)

        if body:
            for match in re.finditer(pattern, body):
                if match.group(1) not in [p.name for p in positions]:
                    pos = PayloadPosition(
                        name=match.group(1),
                        start_marker='§',
                        end_marker='§',
                        original_value=match.group(1)
                    )
                    positions.append(pos)

        return positions

    def set_payloads(self, position_name: str, payloads: List[str]):
        if self.engine:
            self.engine.set_payloads(position_name, payloads)

    def set_attack_mode(self, mode: AttackMode):
        if self.engine:
            self.engine.set_attack_mode(mode)

    def add_match_pattern(self, pattern: str):
        if self.engine:
            self.engine.add_match_pattern(pattern)

    def execute(self, callback: Callable = None) -> List[IntruderResult]:
        if self.engine:
            return self.engine.execute(callback)
        return []


def create_payload_list(start: int, end: int, values: List[str]) -> List[str]:
    return values[start:end]


if __name__ == '__main__':
    intruder = Intruder()

    request = """GET /test§param§ HTTP/1.1
Host: example.com
User-Agent: Test"""

    if intruder.set_request(request):
        print(f"Positions found: {len(intruder.engine.request.positions)}")
        for pos in intruder.engine.request.positions:
            print(f"  - {pos.name}")

        intruder.set_payloads('param', ['test1', 'test2', 'test3'])
        intruder.set_attack_mode(AttackMode.SNIPER)

        results = intruder.execute()
        print(f"Results: {len(results)}")