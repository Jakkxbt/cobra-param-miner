"""Baseline / noise floor + candidate param probing."""
from __future__ import annotations

import secrets
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Sequence

from . import httpx


def _canary(prefix: str = "zqxk") -> str:
    # unique, unlikely in normal pages; alphanumeric for form/json safety
    tail = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(10))
    return "%s%s" % (prefix, tail)


@dataclass
class Baseline:
    status: int
    length: int
    content_hash: str
    header_keys: frozenset
    noise_floor: int  # max abs length delta between identical probes
    samples: List[int] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class Finding:
    param: str
    confidence: str  # HIGH | MEDIUM
    evidence: str
    status: int
    length: int
    canary: str
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    method: str
    baseline: Optional[Baseline]
    findings: List[Finding] = field(default_factory=list)
    tested: int = 0
    errors: int = 0
    noise_floor: int = 0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "method": self.method,
            "noise_floor": self.noise_floor,
            "tested": self.tested,
            "errors": self.errors,
            "baseline": None
            if not self.baseline
            else {
                "status": self.baseline.status,
                "length": self.baseline.length,
                "content_hash": self.baseline.content_hash,
                "noise_floor": self.baseline.noise_floor,
                "header_count": len(self.baseline.header_keys),
            },
            "findings": [f.to_dict() for f in self.findings],
        }


def measure_baseline(
    url: str,
    method: str = "GET",
    content_type: Optional[str] = None,
    timeout: float = 8.0,
    insecure: bool = False,
    headers: Optional[Dict[str, str]] = None,
    junk_name: str = "zzpmjunk",
) -> Baseline:
    """
    Send the same junk-param request twice.
    noise_floor = abs(len1 - len2); findings must exceed this (plus a small pad).
    """
    junk_val = _canary("junk")
    params = {junk_name: junk_val}
    r1 = httpx.request(
        url,
        method=method,
        params=params,
        content_type=content_type,
        timeout=timeout,
        insecure=insecure,
        headers=headers,
    )
    r2 = httpx.request(
        url,
        method=method,
        params=params,
        content_type=content_type,
        timeout=timeout,
        insecure=insecure,
        headers=headers,
    )
    if r1.error and r1.status == 0 and r2.error and r2.status == 0:
        return Baseline(
            status=0,
            length=0,
            content_hash="",
            header_keys=frozenset(),
            noise_floor=0,
            samples=[],
            error=r1.error or r2.error,
        )
    # Prefer the successful sample as baseline face
    face = r1 if r1.status else r2
    if r2.status and (not r1.status or r2.length):
        # both ok usually — use first for status/hash, lengths from both
        face = r1 if r1.status else r2
    lengths = [r.length for r in (r1, r2) if r.status or r.body is not None]
    if len(lengths) >= 2:
        noise = abs(lengths[0] - lengths[1])
    else:
        noise = 0
    # small pad so tiny jitter does not cry wolf
    noise_floor = noise  # detection uses > noise_floor
    return Baseline(
        status=face.status,
        length=face.length,
        content_hash=face.content_hash,
        header_keys=face.header_keys,
        noise_floor=noise_floor,
        samples=lengths,
        error=None if face.status or face.body else (face.error or "baseline failed"),
    )


def _canary_reflected(result: httpx.ProbeResult, canary: str) -> Optional[str]:
    if canary and canary in (result.body or ""):
        return "body"
    for hk, hv in (result.headers or {}).items():
        if canary in hv:
            return "header:%s" % hk
    return None


def _classify(
    result: httpx.ProbeResult,
    baseline: Baseline,
    canary: str,
    param: str,
) -> Optional[Finding]:
    if result.error and result.status == 0:
        return None

    where = _canary_reflected(result, canary)
    if where:
        return Finding(
            param=param,
            confidence="HIGH",
            evidence="canary reflected in %s" % where,
            status=result.status,
            length=result.length,
            canary=canary,
            detail="Parameter value is read and echoed — strong signal the param is accepted.",
        )

    reasons: List[str] = []
    if result.status != baseline.status:
        reasons.append("status %s→%s" % (baseline.status, result.status))

    delta = abs(result.length - baseline.length)
    # Beyond noise floor: strictly greater than measured noise
    if delta > baseline.noise_floor:
        sign = "+" if result.length >= baseline.length else "-"
        reasons.append(
            "len %s%d over floor (floor=%d, base=%d, now=%d)"
            % (sign, delta, baseline.noise_floor, baseline.length, result.length)
        )

    if result.content_hash != baseline.content_hash and delta > baseline.noise_floor:
        # hash change alone with length within noise is often dynamic tokens —
        # only count hash if we already saw a length move, OR status change.
        # If length within floor but hash differs, ignore (anti cry-wolf).
        if "len " not in " ".join(reasons) and result.status == baseline.status:
            # pure hash flip within noise → ignore
            pass
        else:
            if "hash" not in " ".join(reasons):
                reasons.append("content hash changed")
    elif (
        result.content_hash != baseline.content_hash
        and result.status != baseline.status
    ):
        reasons.append("content hash changed")

    # New response headers vs baseline
    new_hdrs = result.header_keys - baseline.header_keys
    if new_hdrs and (delta > baseline.noise_floor or result.status != baseline.status):
        reasons.append("new headers: %s" % ",".join(sorted(new_hdrs)[:5]))

    if not reasons:
        return None

    # Require at least status change OR length beyond floor
    meaningful = any(
        r.startswith("status ") or r.startswith("len ") for r in reasons
    )
    if not meaningful:
        return None

    return Finding(
        param=param,
        confidence="MEDIUM",
        evidence="; ".join(reasons),
        status=result.status,
        length=result.length,
        canary=canary,
        detail="Parameter changes response behaviour without reflecting the canary.",
    )


def mine(
    url: str,
    params: Sequence[str],
    method: str = "GET",
    content_type: Optional[str] = None,
    timeout: float = 8.0,
    insecure: bool = False,
    headers: Optional[Dict[str, str]] = None,
    workers: int = 10,
) -> ScanResult:
    workers = max(1, min(int(workers or 10), 10))
    baseline = measure_baseline(
        url,
        method=method,
        content_type=content_type,
        timeout=timeout,
        insecure=insecure,
        headers=headers,
    )
    result = ScanResult(
        target=url,
        method=method.upper(),
        baseline=baseline,
        noise_floor=baseline.noise_floor,
    )
    if baseline.error and baseline.status == 0:
        result.errors += 1
        return result

    # stable unique list
    seen = set()
    candidates: List[str] = []
    for p in params:
        p = (p or "").strip()
        if not p or p in seen:
            continue
        seen.add(p)
        candidates.append(p)

    def work(param: str) -> tuple:
        canary = _canary()
        pr = httpx.request(
            url,
            method=method,
            params={param: canary},
            content_type=content_type,
            timeout=timeout,
            insecure=insecure,
            headers=headers,
        )
        finding = _classify(pr, baseline, canary, param)
        return param, pr, finding

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(work, p): p for p in candidates}
        for fut in as_completed(futs):
            result.tested += 1
            try:
                param, pr, finding = fut.result()
            except Exception:
                result.errors += 1
                continue
            if pr.error and pr.status == 0:
                result.errors += 1
            if finding:
                result.findings.append(finding)

    # stable sort: HIGH first, then name
    order = {"HIGH": 0, "MEDIUM": 1}
    result.findings.sort(key=lambda f: (order.get(f.confidence, 9), f.param))
    return result
