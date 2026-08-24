#!/usr/bin/env python3
"""Minimal webhook sink for local testing.
Logs every POST body to stdout and keeps the last 50 in memory,
viewable at GET /.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone

received = []

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # quiet default access logs; we print our own

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        entry = {
            "time": datetime.now(timezone.utc).isoformat(),
            "path": self.path,
            "body": body,
        }
        try:
            entry["parsed"] = json.loads(body)
        except Exception:
            pass
        received.append(entry)
        del received[:-50]
        print(f"[webhook] {entry['time']} {self.path} -> {body}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"received"}')

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(received, indent=2).encode())

if __name__ == "__main__":
    print("Webhook receiver listening on :8080", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
