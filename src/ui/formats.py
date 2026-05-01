"""Format Support: HTML, JSON, Image Preview"""
from typing import Optional, Dict, List
from dataclasses import dataclass
import base64
import json
from html import escape
from ..core.models import HTTPMessage, MessageType


@dataclass
class FormattedContent:
    content_type: str
    content: str
    is_truncated: bool = False
    error: Optional[str] = None


class JSONFormatter:
    def format(self, body: bytes, indent: int = 2) -> FormattedContent:
        try:
            text = body.decode('utf-8')
            obj = json.loads(text)
            formatted = json.dumps(obj, indent=indent, ensure_ascii=False)

            if len(formatted) > 50000:
                formatted = formatted[:50000]
                return FormattedContent('json', formatted, is_truncated=True)

            return FormattedContent('json', formatted)
        except json.JSONDecodeError as e:
            return FormattedContent('json', str(body), error=f"JSON parse error: {e}")
        except Exception as e:
            return FormattedContent('json', str(body), error=str(e))

    def minify(self, body: bytes) -> FormattedContent:
        try:
            text = body.decode('utf-8')
            obj = json.loads(text)
            minified = json.dumps(obj, separators=(',', ':'))

            return FormattedContent('json', minified)
        except Exception as e:
            return FormattedContent('json', str(body), error=str(e))

    def validate(self, body: bytes) -> tuple[bool, Optional[str]]:
        try:
            json.loads(body.decode('utf-8'))
            return True, None
        except json.JSONDecodeError as e:
            return False, str(e)


class HTMLFormatter:
    def format(self, body: bytes, style: str = 'dark') -> FormattedContent:
        try:
            text = body.decode('utf-8', errors='replace')

            styled_html = self._wrap_with_style(text, style)

            return FormattedContent('html', styled_html)
        except Exception as e:
            return FormattedContent('html', str(body), error=str(e))

    def _wrap_with_style(self, html: str, style: str) -> str:
        if style == 'dark':
            dark_css = '''
            <style>
                body { background: #1e1e1e; color: #d4d4d4; font-family: monospace; padding: 20px; }
                pre { white-space: pre-wrap; word-wrap: break-word; }
                .tag { color: #569cd6; }
                .attr { color: #9cdcfe; }
                .string { color: #ce9178; }
                .comment { color: #6a9955; }
            </style>
            '''
            return f"<html><head>{dark_css}</head><body><pre>{escape(html)}</pre></body></html>"
        else:
            return f"<html><body><pre>{escape(html)}</pre></body></html>"

    def extract_links(self, body: bytes) -> List[str]:
        try:
            import re
            text = body.decode('utf-8', errors='replace')

            hrefs = re.findall(r'href=["\']([^"\']+)["\']', text, re.IGNORECASE)
            srcs = re.findall(r'src=["\']([^"\']+)["\']', text, re.IGNORECASE)

            return list(set(hrefs + srcs))
        except:
            return []

    def extract_forms(self, body: bytes) -> List[Dict]:
        try:
            from bs4 import BeautifulSoup
            text = body.decode('utf-8', errors='replace')
            soup = BeautifulSoup(text, 'html.parser')

            forms = []
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }

                for inp in form.find_all(['input', 'textarea', 'select']):
                    form_data['inputs'].append({
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', '')
                    })

                forms.append(form_data)

            return forms
        except:
            return []


class XMLFormatter:
    def format(self, body: bytes, indent: int = 2) -> FormattedContent:
        try:
            import xml.etree.ElementTree as ET

            text = body.decode('utf-8', errors='replace')
            root = ET.fromstring(text)

            formatted = self._indent_element(root, indent)

            return FormattedContent('xml', formatted)
        except ET.ParseError as e:
            return FormattedContent('xml', str(body), error=f"XML parse error: {e}")
        except Exception as e:
            return FormattedContent('xml', str(body), error=str(e))

    def _indent_element(self, elem, indent: int, level: int = 0) -> str:
        indent_str = ' ' * indent * level
        tail_indent = ' ' * indent * level

        text = elem.text or ''

        children = list(elem)
        if children:
            if not text.strip():
                text = '\n' + indent_str

            result = f"{indent_str}<{elem.tag}"
            for key, value in elem.attrib.items():
                result += f' {key}="{value}"'
            result += ">\n"

            for child in children:
                result += self._indent_element(child, indent, level + 1)

            result += f"{tail_indent}</{elem.tag}>\n"
        else:
            if text.strip():
                result = f"{indent_str}<{elem.tag}>{text}</{elem.tag}>\n"
            else:
                result = f"{indent_str}<{elem.tag}/>\n"

        return result


class ImagePreview:
    SUPPORTED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml', 'image/bmp']

    def can_preview(self, content_type: str) -> bool:
        return any(t in content_type.lower() for t in self.SUPPORTED_TYPES)

    def get_preview_data(self, body: bytes, content_type: str) -> Optional[str]:
        if not self.can_preview(content_type):
            return None

        if 'svg' in content_type.lower():
            return body.decode('utf-8', errors='replace')

        b64 = base64.b64encode(body).decode('utf-8')

        mime_type = 'image/jpeg'
        if 'png' in content_type.lower():
            mime_type = 'image/png'
        elif 'gif' in content_type.lower():
            mime_type = 'image/gif'
        elif 'webp' in content_type.lower():
            mime_type = 'image/webp'
        elif 'bmp' in content_type.lower():
            mime_type = 'image/bmp'

        return f"data:{mime_type};base64,{b64}"

    def get_image_info(self, body: bytes) -> Dict:
        info = {'size': len(body), 'type': 'unknown'}

        if body[:2] == b'\xff\xd8':
            info['type'] = 'JPEG'
        elif body[:8] == b'\x89PNG\r\n\x1a\n':
            info['type'] = 'PNG'
        elif body[:6] in [b'GIF87a', b'GIF89a']:
            info['type'] = 'GIF'
        elif body[:4] == b'RIFF' and body[8:12] == b'WEBP':
            info['type'] = 'WebP'
        elif body[:2] == b'BM':
            info['type'] = 'BMP'

        return info


class FormatDetector:
    def __init__(self):
        self.json_fmt = JSONFormatter()
        self.html_fmt = HTMLFormatter()
        self.xml_fmt = XMLFormatter()
        self.image_prev = ImagePreview()

    def detect_and_format(self, message: HTTPMessage) -> FormattedContent:
        if not message.body:
            return FormattedContent('text', '[No body]')

        content_type = message.content_type or ''

        if message.is_json:
            return self.json_fmt.format(message.body)

        if 'text/html' in content_type:
            return self.html_fmt.format(message.body)

        if 'application/xml' in content_type or 'text/xml' in content_type:
            return self.xml_fmt.format(message.body)

        if 'text/plain' in content_type:
            return FormattedContent('text', message.body.decode('utf-8', errors='replace'))

        if self.image_prev.can_preview(content_type):
            preview = self.image_prev.get_preview_data(message.body, content_type)
            if preview:
                return FormattedContent('image', preview)

        return FormattedContent('binary', f"[{len(message.body)} bytes - binary content]")


if __name__ == '__main__':
    from src.core.models import HTTPMessage, MessageType, Protocol

    json_msg = HTTPMessage(
        type=MessageType.RESPONSE,
        status_code=200,
        body=b'{"key": "value", "nested": {"a": 1}}'
    )

    fmt = JSONFormatter()
    result = fmt.format(json_msg.body)
    print("JSON formatted:")
    print(result.content)

    print("\n" + "="*40 + "\n")

    html_msg = HTTPMessage(
        type=MessageType.RESPONSE,
        status_code=200,
        body=b'<html><body><h1>Hello</h1></body></html>'
    )

    html_fmt = HTMLFormatter()
    result = html_fmt.format(html_msg.body)
    print("HTML formatted (first 100 chars):")
    print(result.content[:100])