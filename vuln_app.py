#!/usr/bin/env python3
"""
Lab target: reflects `name` and changes output when hidden `debug=1` is set.
Unknown params are ignored (no length/status change).
"""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: str, content_type: str = "text/html; charset=utf-8"):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _params(self) -> dict:
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query, keep_blank_values=True)
        # flatten first value
        out = {k: (v[0] if v else "") for k, v in q.items()}
        if self.command == "POST":
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            ctype = (self.headers.get("Content-Type") or "").lower()
            if "json" in ctype:
                try:
                    obj = json.loads(raw.decode() or "{}")
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            out[str(k)] = "" if v is None else str(v)
                except Exception:
                    pass
            else:
                form = parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
                for k, v in form.items():
                    out[k] = v[0] if v else ""
        return out

    def _handle(self):
        p = self._params()
        name = p.get("name", "")
        debug = p.get("debug", "")
        # Reflect name (HIGH signal when canary used)
        lines = [
            "<html><body>",
            "<h1>greeter</h1>",
            "<p>Hello %s</p>" % (name if name else "world"),
        ]
        # Hidden behaviour: any non-empty debug value adds a fixed extra block
        # (length/hash change without echoing the canary → MEDIUM for miners).
        if debug:
            lines.append("<pre id='debug'>DEBUG_MODE=on secrets=lab-only</pre>")
        lines.append("</body></html>")
        # Unknown params intentionally ignored
        self._send(200, "\n".join(lines))

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def log_message(self, *a):
        return


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18350)
    args = ap.parse_args(argv)
    sys.stderr.write("vuln_app on http://127.0.0.1:%d/  (name reflect + debug)\n" % args.port)
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
