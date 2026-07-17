"""CLI for param-miner."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from . import __version__
from .miner import ScanResult, mine
from .wordlist import DEFAULT_PARAMS


BANNER = """\
param-miner — hidden / unlinked parameter discovery
Authorised recon only. Baseline noise floor filters false positives.
"""


def _parse_headers(items: Optional[List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in items or []:
        if ":" not in raw:
            raise SystemExit("invalid --header %r (want Name: value)" % raw)
        k, v = raw.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def _load_wordlist(path: Optional[str]) -> List[str]:
    if not path:
        return list(DEFAULT_PARAMS)
    p = Path(path).expanduser()
    if not p.is_file():
        raise SystemExit("wordlist not found: %s" % p)
    out: List[str] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # first token only
        out.append(line.split()[0])
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="param-miner",
        description=(
            "Find hidden/unlinked parameters an endpoint secretly accepts. "
            "HIGH = canary reflected; MEDIUM = behaviour change beyond noise floor."
        ),
        epilog=(
            "Examples:\n"
            "  param-miner 'http://127.0.0.1:18350/'\n"
            "  param-miner -u http://127.0.0.1:18350/ -X POST --content-type application/json\n"
            "  param-miner -u http://target/search --wordlist params.txt --json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("url", nargs="?", help="Target URL")
    p.add_argument("-u", "--url", dest="url_flag", help="Target URL")
    p.add_argument(
        "-X",
        "--method",
        default="GET",
        choices=["GET", "POST", "get", "post"],
        help="HTTP method (default: GET)",
    )
    p.add_argument(
        "--content-type",
        default=None,
        help="POST body type: application/x-www-form-urlencoded or application/json",
    )
    p.add_argument(
        "-w",
        "--wordlist",
        default=None,
        help="Override built-in wordlist (one param per line)",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Thread pool size, max 10 (default: 10)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Per-request timeout seconds (default: 8)",
    )
    p.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verify")
    p.add_argument(
        "-H",
        "--header",
        action="append",
        dest="headers",
        metavar="Name: value",
        help="Extra request header (repeatable)",
    )
    p.add_argument("--json", dest="json_out", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--version", action="version", version="param-miner %s" % __version__)
    return p


def _print_human(result: ScanResult, quiet: bool = False) -> None:
    if not quiet:
        sys.stdout.write(BANNER)
        sys.stdout.write("Target  : %s (%s)\n" % (result.target, result.method))
        if result.baseline:
            sys.stdout.write(
                "Baseline: status=%s len=%s noise_floor=%s\n"
                % (
                    result.baseline.status,
                    result.baseline.length,
                    result.baseline.noise_floor,
                )
            )
        sys.stdout.write("Tested  : %d params\n\n" % result.tested)

    if result.baseline and result.baseline.error and result.baseline.status == 0:
        sys.stdout.write("ERROR: baseline failed: %s\n" % result.baseline.error)
        return

    if not result.findings:
        sys.stdout.write("No hidden parameters found (above noise floor).\n")
        return

    for f in result.findings:
        sys.stdout.write("[%s] %s\n" % (f.confidence, f.param))
        sys.stdout.write("  evidence : %s\n" % f.evidence)
        sys.stdout.write("  status   : %s  len=%s  canary=%s\n" % (f.status, f.length, f.canary))
        if f.detail:
            sys.stdout.write("  detail   : %s\n" % f.detail)
        sys.stdout.write("\n")

    n_h = sum(1 for f in result.findings if f.confidence == "HIGH")
    n_m = sum(1 for f in result.findings if f.confidence == "MEDIUM")
    sys.stdout.write("Summary: %d HIGH, %d MEDIUM\n" % (n_h, n_m))


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    url = args.url_flag or args.url
    if not url:
        build_parser().print_help()
        return 2
    if not urlsplit(url).scheme:
        sys.stderr.write("error: URL must include scheme (http:// or https://)\n")
        return 2

    try:
        headers = _parse_headers(args.headers)
    except SystemExit as e:
        sys.stderr.write("error: %s\n" % e)
        return 2

    try:
        wordlist = _load_wordlist(args.wordlist)
    except SystemExit as e:
        sys.stderr.write("error: %s\n" % e)
        return 2

    method = args.method.upper()
    if method == "POST" and not args.content_type:
        content_type = "application/x-www-form-urlencoded"
    else:
        content_type = args.content_type

    result = mine(
        url=url,
        params=wordlist,
        method=method,
        content_type=content_type,
        timeout=args.timeout,
        insecure=args.insecure,
        headers=headers or None,
        workers=args.workers,
    )

    if args.json_out:
        sys.stdout.write(json.dumps(result.to_dict(), indent=2) + "\n")
    else:
        _print_human(result, quiet=args.quiet)

    if result.baseline and result.baseline.error and result.baseline.status == 0:
        return 3
    if result.findings:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
