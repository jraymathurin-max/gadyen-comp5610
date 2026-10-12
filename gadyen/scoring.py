"""Deterministic scoring engine. The LLM never decides pass/fail: these rules do.

Each control returns one of: pass, warn, fail, unknown.
"""
import re
from dataclasses import asdict, dataclass

PASS, WARN, FAIL, UNKNOWN = "pass", "warn", "fail", "unknown"


@dataclass
class Finding:
    control_id: str
    title: str
    status: str
    severity: str          # critical, high, medium, low
    detail: str
    reference: str
    target: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


FTC = "FTC Safeguards Rule 16 CFR 314.4"
IRS = "IRS Pub. 4557 / Pub. 5708"
MA = "201 CMR 17.00"


def latest_scans(evidence_rows: list) -> dict:
    """{(tool, target): payload} keeping the most recent scan of each kind."""
    latest = {}
    for row in evidence_rows:
        if row["kind"] == "scan":
            latest[(row["tool"], row["target"])] = row["payload"]
    return latest


# ---------------------------------------------------------------- network rules
def email_rules(target: str, r: dict) -> list:
    out = []
    spf = r.get("spf")
    failed = r.get("lookup_failed") or []
    if "spf" in failed:
        out.append(Finding("EMAIL-1", "SPF record", UNKNOWN, "high",
                           "DNS lookup failed; SPF could not be checked. Re-run later.", FTC, target))
    elif r.get("spf_record_count", 0) > 1:
        out.append(Finding("EMAIL-1", "SPF record", FAIL, "high",
                           "More than one SPF record: receivers will treat SPF as broken.", FTC, target))
    elif spf is None:
        out.append(Finding("EMAIL-1", "SPF record", FAIL, "high",
                           "No SPF record: anyone can send email pretending to be this domain.", FTC, target))
    elif spf["all_qualifier"] in ("+", "?", None):
        out.append(Finding("EMAIL-1", "SPF record", FAIL, "high",
                           f"SPF ends with a permissive or missing 'all' ({spf['all_qualifier']}).", FTC, target))
    elif spf["dns_lookups"] > 10:
        out.append(Finding("EMAIL-1", "SPF record", WARN, "medium",
                           "SPF needs more than 10 DNS lookups and may fail.", FTC, target))
    else:
        out.append(Finding("EMAIL-1", "SPF record", PASS, "high", "SPF is present and restrictive.", FTC, target))

    dmarc = r.get("dmarc")
    if "dmarc" in failed:
        out.append(Finding("EMAIL-2", "DMARC policy", UNKNOWN, "high",
                           "DNS lookup failed; DMARC could not be checked. Re-run later.", FTC, target))
    elif dmarc is None:
        out.append(Finding("EMAIL-2", "DMARC policy", FAIL, "high",
                           "No DMARC record: spoofed emails using this domain are not blocked.", FTC, target))
    elif dmarc["policy"] in ("quarantine", "reject"):
        out.append(Finding("EMAIL-2", "DMARC policy", PASS, "high",
                           f"DMARC policy is '{dmarc['policy']}'.", FTC, target))
    else:
        out.append(Finding("EMAIL-2", "DMARC policy", WARN, "high",
                           "DMARC is in monitoring mode (p=none): spoofed emails still get delivered.", FTC, target))

    if r.get("dkim_selectors_found"):
        out.append(Finding("EMAIL-3", "DKIM signing", PASS, "medium",
                           "DKIM key found for selector(s) " + ", ".join(r["dkim_selectors_found"]) + ".", FTC, target))
    else:
        out.append(Finding("EMAIL-3", "DKIM signing", WARN, "medium",
                           "No DKIM key found with common selectors (it may use a custom selector).", FTC, target))
    return out


def tls_rules(target: str, r: dict) -> list:
    if not r.get("reachable", True):
        return [Finding("TLS-1", "HTTPS certificate", UNKNOWN, "high", "Host not reachable on port 443.", MA, target)]
    out = []
    if not r.get("cert_valid"):
        out.append(Finding("TLS-1", "HTTPS certificate", FAIL, "high",
                           f"Certificate is not valid: {r.get('error', 'unknown error')}.", MA, target))
    elif r.get("days_until_expiry", 0) < 14:
        out.append(Finding("TLS-1", "HTTPS certificate", WARN, "high",
                           f"Certificate expires in {r['days_until_expiry']} days.", MA, target))
    else:
        out.append(Finding("TLS-1", "HTTPS certificate", PASS, "high",
                           f"Valid certificate, {r['days_until_expiry']} days left ({r.get('protocol')}).", MA, target))
    old = [v for v, k in (("TLS 1.0", "accepts_tls1_0"), ("TLS 1.1", "accepts_tls1_1")) if r.get(k)]
    if old:
        out.append(Finding("TLS-2", "Outdated TLS versions", FAIL, "medium",
                           "Server still accepts " + " and ".join(old) + ".", MA, target))
    elif r.get("accepts_tls1_0") is None and r.get("accepts_tls1_1") is None:
        out.append(Finding("TLS-2", "Outdated TLS versions", UNKNOWN, "medium",
                           "Could not test old TLS versions from this scanner.", MA, target))
    else:
        out.append(Finding("TLS-2", "Outdated TLS versions", PASS, "medium",
                           "TLS 1.0 and 1.1 are refused.", MA, target))
    return out


VERSION_RE = re.compile(r"\d+\.\d+")


def http_rules(target: str, r: dict) -> list:
    if not r.get("reachable"):
        return [Finding("WEB-1", "HTTPS website", UNKNOWN, "medium", "Website not reachable over HTTPS.", MA, target)]
    out = [Finding("WEB-1", "HSTS header", PASS if r.get("hsts") else WARN, "medium",
                   "HSTS is set." if r.get("hsts") else "No HSTS header: browsers may be downgraded to HTTP.",
                   MA, target)]
    redirect = r.get("http_redirects_to_https")
    if redirect is False:
        out.append(Finding("WEB-2", "HTTP to HTTPS redirect", FAIL, "high",
                           "The site answers over plain HTTP without redirecting to HTTPS.", MA, target))
    else:
        out.append(Finding("WEB-2", "HTTP to HTTPS redirect", PASS, "high",
                           "Plain HTTP is redirected or closed.", MA, target))
    leaks = [v for v in (r.get("server"), r.get("x_powered_by"), r.get("generator")) if v and VERSION_RE.search(v)]
    out.append(Finding("WEB-3", "Software version disclosure", WARN if leaks else PASS, "low",
                       ("Software versions are visible: " + "; ".join(leaks)[:150]) if leaks
                       else "No software version disclosed.", FTC, target))
    return out


def port_rules(target: str, r: dict) -> list:
    if r.get("open"):
        names = ", ".join(f"{p['service']} ({p['port']})" for p in r["open"])
        return [Finding("NET-1", "Risky services exposed", FAIL, "critical",
                        f"Reachable from the Internet: {names}.", FTC, target)]
    return [Finding("NET-1", "Risky services exposed", PASS, "critical",
                    "None of the risky ports checked are open.", FTC, target)]


RULES = {"check_email_auth": email_rules, "check_tls": tls_rules,
         "check_http_headers": http_rules, "check_exposed_services": port_rules}


# ---------------------------------------------------------------- questionnaire rules
def answer_rules(a: dict) -> list:
    def yn(qid, cid, title, sev, ref, good, bad):
        v = a.get(qid)
        if v is None:
            return Finding(cid, title, UNKNOWN, sev, "Question not answered.", ref)
        if v == "yes":
            return Finding(cid, title, PASS, sev, good, ref)
        return Finding(cid, title, FAIL if v == "no" else WARN, sev, bad, ref)

    out = [
        Finding("ORG-1", "Qualified Individual designated",
                PASS if a.get("Q04") else (UNKNOWN if "Q04" not in a else FAIL), "high",
                "A person is responsible for security." if a.get("Q04")
                else "Nobody is designated as responsible for security.", FTC),
        yn("Q06", "ACC-1", "MFA on email", "critical", FTC,
           "MFA is on for all email accounts.", "MFA is not confirmed on every email account."),
        yn("Q07", "ACC-2", "MFA on tax software and portals", "critical", FTC + " / " + IRS,
           "MFA is on for tax software and portals.", "MFA is not confirmed on tax software or portals."),
        yn("Q12", "ORG-3", "Annual security training", "medium", FTC,
           "Staff trained in the last 12 months.", "No confirmed security training in the last 12 months."),
        yn("Q13", "ORG-4", "Incident response plan", "high", FTC + " / " + IRS,
           "A written incident plan exists.", "No written incident response plan."),
        yn("Q14", "ORG-5", "Service provider oversight", "medium", FTC,
           "Vendors are listed and reviewed.", "Vendors handling client data are not tracked or reviewed."),
    ]
    backups = a.get("Q09")
    out.append(Finding("ORG-2", "Tested backups",
                       {"yes_tested": PASS, "yes_not_tested": WARN, "no": FAIL}.get(backups, UNKNOWN),
                       "high", {"yes_tested": "Backups exist and restore was tested.",
                                "yes_not_tested": "Backups exist but restore was never tested.",
                                "no": "No backups of client data."}.get(backups, "Question not answered."), IRS))
    disposal = a.get("Q15")
    out.append(Finding("ORG-6", "Secure disposal",
                       {"shred_and_wipe": PASS, "shred_only": WARN, "trash": FAIL, "not_sure": WARN}.get(disposal, UNKNOWN),
                       "medium", {"shred_and_wipe": "Paper is shredded and drives are wiped.",
                                  "shred_only": "Paper is shredded but old drives are not securely wiped.",
                                  "trash": "Client records may be thrown away without destruction.",
                                  "not_sure": "Disposal practice is unclear."}.get(disposal, "Question not answered."), FTC))
    wifi = a.get("Q10")
    out.append(Finding("NET-2", "Separate guest Wi-Fi",
                       {"yes": PASS, "no_wifi": PASS, "no": WARN}.get(wifi, UNKNOWN), "medium",
                       "Visitors share the office network." if wifi == "no" else "Guest traffic is separated or no Wi-Fi.",
                       IRS))
    remote = a.get("Q11")
    out.append(Finding("NET-3", "Secure remote access",
                       {"remote_desktop_rdp": FAIL}.get(remote, PASS if remote else UNKNOWN), "critical",
                       "Remote Desktop used directly over the Internet (common ransomware entry point)."
                       if remote == "remote_desktop_rdp" else "Remote access method acceptable or none.", IRS))
    places = a.get("Q08") or []
    out.append(Finding("DATA-1", "Portable storage of client data",
                       WARN if ("usb_drives" in places or "laptops" in places) else PASS, "high",
                       "Client data on laptops or USB drives must be encrypted (Massachusetts law)."
                       if ("usb_drives" in places or "laptops" in places) else "No portable storage reported.", MA))
    return out


# ---------------------------------------------------------------- endpoint rules
def endpoint_rules(reports: list) -> list:
    if not reports:
        return [Finding("END-0", "Computer self-checks", UNKNOWN, "high",
                        "No computer self-check uploaded yet.", IRS)]
    out = []
    checks = [("END-1", "Disk encryption", "disk_encrypted", "critical", MA),
              ("END-2", "Firewall enabled", "firewall_enabled", "high", IRS),
              ("END-3", "Antivirus enabled", "antivirus_enabled", "high", IRS),
              ("END-4", "Automatic updates", "auto_updates_enabled", "high", IRS)]
    for cid, title, key, sev, ref in checks:
        bad = [r["hostname"] for r in reports if r.get(key) is False]
        unknown = [r["hostname"] for r in reports if r.get(key) is None]
        status = FAIL if bad else (UNKNOWN if unknown else PASS)
        detail = (f"Not enabled on: {', '.join(bad)}." if bad else
                  f"Could not be read on: {', '.join(unknown)}." if unknown else "Enabled on all computers.")
        out.append(Finding(cid, title, status, sev, detail, ref))
    slow = [r["hostname"] for r in reports
            if r.get("screen_lock_minutes") is not None and (r["screen_lock_minutes"] == 0 or r["screen_lock_minutes"] > 15)]
    out.append(Finding("END-5", "Automatic screen lock", WARN if slow else PASS, "medium",
                       f"Screen lock missing or longer than 15 minutes on: {', '.join(slow)}." if slow
                       else "Screen lock of 15 minutes or less (where readable).", IRS))
    return out


# ---------------------------------------------------------------- overall
def evaluate(evidence_rows: list, answers: dict, endpoint_reports: list) -> list:
    findings = []
    for (tool, target), payload in latest_scans(evidence_rows).items():
        rule = RULES.get(tool)
        if rule:
            findings.extend(rule(target, payload))
    findings.extend(answer_rules(answers))
    findings.extend(endpoint_rules(endpoint_reports))
    return findings


def overall_risk(findings: list) -> str:
    if any(f.status == FAIL and f.severity == "critical" for f in findings):
        return "high"
    fails = sum(f.status == FAIL for f in findings)
    warns = sum(f.status == WARN for f in findings)
    if fails >= 2 or (fails and warns >= 3):
        return "high"
    if fails or warns >= 3:
        return "medium"
    return "low"
