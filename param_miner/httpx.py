"""Minimal stdlib HTTP helper for param probes."""
from __future__ import annotations

import hashlib
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


@dataclass
class ProbeResult:
    url: str
    status: int
    body: str
    headers: Dict[str, str] = field(default_factory=dict)
    length: int = 0
    content_hash: str = ""
    error: Optional[str] = None

    @property
    def header_keys(self) -> frozenset:
        return frozenset(self.headers.keys())


def _hash_body(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()


def request(
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, str]] = None,
    content_type: Optional[str] = None,
    timeout: float = 8.0,
    insecure: bool = False,
    max_body: int = 512_000,
    headers: Optional[Dict[str, str]] = None,
) -> ProbeResult:
    """
    Issue one request.

    GET: merge params into query string.
    POST: send params as form-urlencoded or JSON based on content_type.
    """
    method = (method or "GET").upper()
    params = dict(params or {})
    hdrs = {
        "User-Agent": "param-miner/1.0 (+authorised-recon)",
        "Accept": "*/*",
    }
    if headers:
        hdrs.update(headers)

    data: Optional[bytes] = None
    final_url = url

    if method == "GET":
        parts = urllib.parse.urlsplit(url)
        q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        # drop existing keys we are overriding
        override = set(params)
        q = [(k, v) for k, v in q if k not in override]
        q.extend(params.items())
        query = urllib.parse.urlencode(q, doseq=True)
        final_url = urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path, query, parts.fragment)
        )
    else:
        ctype = (content_type or "application/x-www-form-urlencoded").lower()
        if "json" in ctype:
            data = json.dumps(params).encode("utf-8")
            hdrs["Content-Type"] = content_type or "application/json"
        else:
            data = urllib.parse.urlencode(params).encode("utf-8")
            hdrs["Content-Type"] = content_type or "application/x-www-form-urlencoded"

    ctx = None
    if final_url.lower().startswith("https"):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(final_url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(max_body + 1)[:max_body]
            try:
                body = raw.decode("utf-8", errors="replace")
            except Exception:
                body = raw.decode("latin-1", errors="replace")
            rh = {k.lower(): v for k, v in resp.headers.items()}
            return ProbeResult(
                url=resp.geturl(),
                status=getattr(resp, "status", 200) or 200,
                body=body,
                headers=rh,
                length=len(body),
                content_hash=_hash_body(body),
            )
    except urllib.error.HTTPError as e:
        raw = b""
        try:
            raw = e.read(max_body)
        except Exception:
            pass
        try:
            body = raw.decode("utf-8", errors="replace")
        except Exception:
            body = ""
        rh = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        return ProbeResult(
            url=final_url,
            status=e.code,
            body=body,
            headers=rh,
            length=len(body),
            content_hash=_hash_body(body),
            error="http_error",
        )
    except Exception as e:
        return ProbeResult(
            url=final_url,
            status=0,
            body="",
            length=0,
            content_hash=_hash_body(""),
            error=str(e)[:200],
        )
