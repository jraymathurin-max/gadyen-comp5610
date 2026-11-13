"""Passive DNS checks: domain ownership verification and email authentication."""
import dns.exception
import dns.resolver

DEFAULT_DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "k1", "s1", "dkim"]


def txt_records(name: str):
    """Return the TXT strings published at `name`: [] if the name has none,
    None if the lookup itself FAILED (timeout, broken DNS). Never confuse the two:
    'no record' is a finding, 'lookup failed' is unknown."""
    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=10)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answer]


def verify_domain(domain: str, token: str) -> dict:
    """The owner proves control by publishing TXT 'gadyen-verify=<token>'
    at _gadyen-verify.<domain>."""
    records = txt_records(f"_gadyen-verify.{domain}") or []
    return {"domain": domain, "verified": f"gadyen-verify={token}" in records}


def parse_spf(record: str) -> dict:
    terms = record.lower().split()
    all_term = next((t for t in terms if t.lstrip("+-~?") == "all"), None)
    qualifier = None
    if all_term:
        qualifier = all_term[0] if all_term[0] in "+-~?" else "+"
    lookups = 0
    for term in terms[1:]:
        mech = term.lstrip("+-~?")
        if mech in ("a", "mx", "ptr") or mech.startswith(
                ("a:", "a/", "mx:", "mx/", "ptr:", "include:", "exists:", "redirect=")):
            lookups += 1
    return {"record": record, "all_qualifier": qualifier, "dns_lookups": lookups}


def parse_dmarc(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return {"record": record, "policy": tags.get("p", "").lower() or None,
            "rua": tags.get("rua"), "pct": tags.get("pct", "100")}


def check_email_auth(domain: str, dkim_selectors: list = None) -> dict:
    failed = []
    root = txt_records(domain)
    if root is None:
        failed.append("spf")
    dmarc_recs = txt_records(f"_dmarc.{domain}")
    if dmarc_recs is None:
        failed.append("dmarc")
    spf = [r for r in (root or []) if r.lower().startswith("v=spf1")]
    dmarc = [r for r in (dmarc_recs or []) if r.lower().startswith("v=dmarc1")]
    found_dkim = []
    for selector in (dkim_selectors or DEFAULT_DKIM_SELECTORS)[:8]:
        recs = txt_records(f"{selector}._domainkey.{domain}") or []
        if any("p=" in r for r in recs):
            found_dkim.append(selector)
    return {
        "domain": domain,
        "spf": parse_spf(spf[0]) if len(spf) == 1 else None,
        "spf_record_count": len(spf),
        "dmarc": parse_dmarc(dmarc[0]) if dmarc else None,
        "dkim_selectors_found": found_dkim,
        "lookup_failed": failed,
    }
