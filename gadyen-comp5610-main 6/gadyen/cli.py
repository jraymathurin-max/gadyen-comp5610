"""Command-line quick check (no LLM, no database) - your first milestone.

    python -m gadyen.cli quickcheck yourdomain.com
    python -m gadyen.cli quickcheck yourdomain.com --i-own-this-domain

Without the flag only passive DNS checks run. Active checks (TLS, HTTP, ports) run
only on a domain you own or are authorized in writing to test."""
import argparse
import json

from . import scoring
from .scope import ScopeError, normalize_domain, resolve_public_ips
from .tools import dns_tools, http_tools, port_tools, tls_tools


def quickcheck(domain: str, authorized: bool) -> list:
    rows = [{"kind": "scan", "tool": "check_email_auth", "target": domain,
             "payload": dns_tools.check_email_auth(domain)}]
    if authorized:
        resolve_public_ips(domain)
        for tool, fn in (("check_tls", tls_tools.check_tls),
                         ("check_http_headers", http_tools.check_http_headers),
                         ("check_exposed_services", port_tools.check_exposed_services)):
            rows.append({"kind": "scan", "tool": tool, "target": domain, "payload": fn(domain)})
    findings = []
    for (tool, target), payload in scoring.latest_scans(rows).items():
        findings.extend(scoring.RULES[tool](target, payload))
    return findings


def main():
    parser = argparse.ArgumentParser(prog="gadyen")
    sub = parser.add_subparsers(dest="cmd", required=True)
    qc = sub.add_parser("quickcheck")
    qc.add_argument("domain")
    qc.add_argument("--i-own-this-domain", action="store_true")
    qc.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        domain = normalize_domain(args.domain)
        findings = quickcheck(domain, args.i_own_this_domain)
    except ScopeError as exc:
        raise SystemExit(f"Refused: {exc}") from None
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return
    icons = {"pass": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]", "unknown": "[ ?? ]"}
    for f in findings:
        print(f"{icons[f.status]} {f.control_id:8} {f.title}: {f.detail}")
    print("Overall risk (external checks only):", scoring.overall_risk(findings))


if __name__ == "__main__":
    main()
