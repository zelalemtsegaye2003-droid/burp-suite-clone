"""Proxy Request/Response Database"""
import sqlite3
from datetime import datetime
from typing import Optional, List, Dict, Any
import json


class ProxyDatabase:
    def __init__(self, db_path: str = "proxy_history.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                host TEXT,
                path TEXT,
                headers TEXT,
                body BLOB,
                timestamp TEXT NOT NULL,
                is_https INTEGER DEFAULT 0
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER,
                status_code INTEGER,
                status_text TEXT,
                headers TEXT,
                body BLOB,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (request_id) REFERENCES requests(id)
            )
        ''')

        conn.commit()
        conn.close()

    def save_request(self, method: str, url: str, headers: dict,
                     body: Optional[bytes], host: str, path: str) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO requests (method, url, headers, body, host, path, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (method, url, json.dumps(headers), body, host, path,
              datetime.now().isoformat()))

        request_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return request_id

    def save_response(self, request_id: int, status_code: int,
                      status_text: str, headers: dict, body: Optional[bytes]):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO responses (request_id, status_code, status_text, headers, body, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (request_id, status_code, status_text, json.dumps(headers), body,
              datetime.now().isoformat()))

        conn.commit()
        conn.close()

    def get_requests(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, method, url, host, path, timestamp
            FROM requests
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))

        results = []
        for row in cursor.fetchall():
            results.append({
                'id': row[0],
                'method': row[1],
                'url': row[2],
                'host': row[3],
                'path': row[4],
                'timestamp': row[5]
            })

        conn.close()
        return results

    def get_request_detail(self, request_id: int) -> Optional[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM requests WHERE id = ?', (request_id,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            return None

        request = {
            'id': row[0],
            'method': row[1],
            'url': row[2],
            'host': row[3],
            'path': row[4],
            'headers': json.loads(row[5]) if row[5] else {},
            'body': row[6],
            'timestamp': row[7],
            'is_https': bool(row[8])
        }

        cursor.execute('SELECT * FROM responses WHERE request_id = ?', (request_id,))
        resp_row = cursor.fetchone()

        if resp_row:
            request['response'] = {
                'id': resp_row[0],
                'status_code': resp_row[2],
                'status_text': resp_row[3],
                'headers': json.loads(resp_row[4]) if resp_row[4] else {},
                'body': resp_row[5],
                'timestamp': resp_row[6]
            }

        conn.close()
        return request

    def search_requests(self, keyword: str) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, method, url, host, path, timestamp
            FROM requests
            WHERE url LIKE ? OR method LIKE ?
            ORDER BY id DESC
            LIMIT 100
        ''', (f'%{keyword}%', f'%{keyword}%'))

        results = []
        for row in cursor.fetchall():
            results.append({
                'id': row[0],
                'method': row[1],
                'url': row[2],
                'host': row[3],
                'path': row[4],
                'timestamp': row[5]
            })

        conn.close()
        return results

    def delete_request(self, request_id: int):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('DELETE FROM responses WHERE request_id = ?', (request_id,))
        cursor.execute('DELETE FROM requests WHERE id = ?', (request_id,))

        conn.commit()
        conn.close()

    def clear_all(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('DELETE FROM responses')
        cursor.execute('DELETE FROM requests')

        conn.commit()
        conn.close()