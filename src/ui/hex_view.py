"""Hex View for Binary Content"""
from typing import Optional, List
from ..core.models import HTTPMessage


class HexViewRenderer:
    def __init__(self, bytes_per_line: int = 16, show_ascii: bool = True):
        self.bytes_per_line = bytes_per_line
        self.show_ascii = show_ascii

    def render(self, data: bytes, offset: int = 0, length: int = 0) -> str:
        if not data:
            return "(empty)"

        if length == 0:
            length = len(data)

        lines = []
        lines.append("Hex View")
        lines.append("=" * 60)
        lines.append(f"Total size: {length} bytes")
        lines.append("=" * 60)
        lines.append("")

        data = data[offset:offset + length]

        for i in range(0, len(data), self.bytes_per_line):
            chunk = data[i:i + self.bytes_per_line]

            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            hex_part = hex_part.ljust(self.bytes_per_line * 3 - 1)

            if self.show_ascii:
                ascii_part = ''.join(
                    chr(b) if 32 <= b < 127 else '.'
                    for b in chunk
                )
                line = f"{offset + i:08x}  {hex_part}  |{ascii_part}|"
            else:
                line = f"{offset + i:08x}  {hex_part}"

            lines.append(line)

        return '\n'.join(lines)

    def render_message(self, message: HTTPMessage) -> str:
        if not message.body:
            return "No body content"

        return self.render(message.body)


class HexEditor:
    def __init__(self):
        pass

    def replace_bytes(self, data: bytes, search: bytes, replace: bytes) -> bytes:
        return data.replace(search, replace)

    def insert_bytes(self, data: bytes, offset: int, insert: bytes) -> bytes:
        return data[:offset] + insert + data[offset:]

    def delete_bytes(self, data: bytes, offset: int, length: int) -> bytes:
        return data[:offset] + data[offset + length:]

    def find_bytes(self, data: bytes, pattern: bytes) -> List[int]:
        positions = []
        start = 0
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        return positions

    def find_text(self, data: bytes, text: str) -> List[int]:
        return self.find_bytes(data, text.encode('utf-8'))


class HexViewer:
    def __init__(self):
        self.renderer = HexViewRenderer()
        self.editor = HexEditor()

    def view(self, data: bytes, offset: int = 0, length: int = 0) -> str:
        return self.renderer.render(data, offset, length)

    def view_message(self, message: HTTPMessage) -> str:
        return self.renderer.render_message(message)

    def search(self, data: bytes, pattern: str, is_hex: bool = False) -> List[int]:
        if is_hex:
            hex_bytes = bytes.fromhex(pattern.replace(' ', ''))
            return self.editor.find_bytes(data, hex_bytes)
        else:
            return self.editor.find_text(data, pattern)

    def replace(self, data: bytes, search: str, replace: str) -> bytes:
        return self.editor.replace_bytes(
            data,
            search.encode('utf-8'),
            replace.encode('utf-8')
        )


if __name__ == '__main__':
    data = b"Hello World! This is a test of binary data.\x00\x01\x02\x03\x04\x05"
    viewer = HexViewer()
    print(viewer.view(data))

    print("\n" + "=" * 60 + "\n")

    positions = viewer.search(data, "test")
    print(f"Found 'test' at positions: {positions}")