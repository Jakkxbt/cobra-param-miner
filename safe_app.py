#!/usr/bin/env python3
"""
Cry-wolf trap: constant response no matter which params are sent.
param-miner must stay SILENT here.
"""
from __future__ import annotations

import argparse
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


CONSTANT = (
    "<html><body><h1>static</h1><p>nothing varies</p></body></html>\n"
)


class Handler(BaseHTTPRequestHandler):
    def _send(self):
        # Drain body if any so clients don't hang
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            try:
                self.rfile.read(n)
            except Exception:
                pass
        raw = CONSTANT.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self._send()

    def do_POST(self):
        self._send()

    def log_message(self, *a):
        return


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18351)
    args = ap.parse_args(argv)
    sys.stderr.write(
        "safe_app on http://127.0.0.1:%d/  (constant body — expect silence)\n" % args.port
    )
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
