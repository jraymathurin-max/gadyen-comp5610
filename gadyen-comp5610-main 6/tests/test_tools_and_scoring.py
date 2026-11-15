import pytest

from gadyen import scoring
from gadyen.questionnaire import validate_answers
from gadyen.tools import dns_tools
from gadyen.tools.endpoint import parse_endpoint_report


def test_email_parsing(monkeypatch):
    records = {
        "mytaxoffice.com": ["v=spf1 include:_spf.google.com ~all", "google-site-verification=x"],
        "_dmarc.mytaxoffice.com": ["v=DMARC1; p=none; rua=mailto:d@mytaxoffice.com"],
        "google._domainkey.mytaxoffice.com": ["v=DKIM1; k=rsa; p=MIIB..."],
    }
    monkeypatch.setattr(dns_tools, "txt_records", lambda name: records.get(name, []))
    r = dns_tools.check_email_auth("mytaxoffice.com")
    assert r["spf"]["all_qualifier"] == "~" and r["spf"]["dns_lookups"] == 1
    assert r["dmarc"]["policy"] == "none" and r["dkim_selectors_found"] == ["google"]
    by_id = {f.control_id: f.status for f in scoring.email_rules("mytaxoffice.com", r)}
    assert by_id == {"EMAIL-1": "pass", "EMAIL-2": "warn", "EMAIL-3": "pass"}


def test_spf_plus_all_fails():
    spf = dns_tools.parse_spf("v=spf1 +all")
    r = {"spf": spf, "spf_record_count": 1, "dmarc": None, "dkim_selectors_found": []}
    statuses = {f.control_id: f.status for f in scoring.email_rules("x.com", r)}
    assert statuses["EMAIL-1"] == "fail" and statuses["EMAIL-2"] == "fail"


def test_open_rdp_is_critical_and_risk_high():
    findings = scoring.port_rules("x.com", {"open": [{"port": 3389, "service": "RDP"}]})
    assert findings[0].status == "fail" and findings[0].severity == "critical"
    assert scoring.overall_risk(findings) == "high"


def test_answers_rules():
    ans = validate_answers({"Q04": "Marie, owner", "Q06": "no", "Q07": "yes", "Q09": "yes_not_tested",
                            "Q11": "remote_desktop_rdp", "Q08": ["laptops"]})
    s = {f.control_id: f.status for f in scoring.answer_rules(ans)}
    assert s["ORG-1"] == "pass" and s["ACC-1"] == "fail" and s["ACC-2"] == "pass"
    assert s["ORG-2"] == "warn" and s["NET-3"] == "fail" and s["DATA-1"] == "warn"


def test_invalid_answers_rejected():
    with pytest.raises(ValueError):
        validate_answers({"Q06": "maybe"})
    with pytest.raises(ValueError):
        validate_answers({"Q99": "yes"})


def test_endpoint_report_validation():
    good = (b'{"hostname":"FRONT-DESK","os":"Windows","os_version":"11","disk_encrypted":false,'
            b'"firewall_enabled":true,"antivirus_enabled":true,"auto_updates_enabled":null,'
            b'"screen_lock_minutes":30,"collected_at":"2026-10-10T10:00:00Z"}')
    report = parse_endpoint_report(good)
    s = {f.control_id: f.status for f in scoring.endpoint_rules([report])}
    assert s["END-1"] == "fail" and s["END-4"] == "unknown" and s["END-5"] == "warn"
    with pytest.raises(ValueError):
        parse_endpoint_report(good[:-1] + b',"run":"rm -rf /"}')
    with pytest.raises(ValueError):
        parse_endpoint_report(b"x" * 30_000)


def test_dns_failure_is_unknown_not_fail(monkeypatch):
    # A timeout must never be reported as "no SPF record".
    monkeypatch.setattr(dns_tools, "txt_records", lambda name: None)
    r = dns_tools.check_email_auth("mytaxoffice.com")
    s = {f.control_id: f.status for f in scoring.email_rules("mytaxoffice.com", r)}
    assert s["EMAIL-1"] == "unknown" and s["EMAIL-2"] == "unknown"
