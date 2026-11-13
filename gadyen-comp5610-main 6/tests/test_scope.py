import pytest

from gadyen.scope import PolicyGuard, ScopeError, is_public_ip, normalize_domain
from gadyen.tools.registry import TOOL_NAMES

from .conftest import fake_resolver


def guard():
    return PolicyGuard({"mytaxoffice.com"}, set(TOOL_NAMES), max_calls_per_tool=3,
                       resolver=fake_resolver)


def test_verified_domain_and_subdomain_allowed():
    g = guard()
    assert g.check("check_email_auth", {"domain": "mytaxoffice.com"}).allowed
    assert g.check("check_tls", {"host": "www.mytaxoffice.com"}).allowed


def test_unverified_domain_refused():
    d = guard().check("check_tls", {"host": "competitor.com"})
    assert not d.allowed and "not a verified domain" in d.reason


def test_lookalike_domain_refused():
    assert not guard().check("check_tls", {"host": "evilmytaxoffice.com"}).allowed


def test_private_resolution_refused():
    d = guard().check("check_tls", {"host": "internal.mytaxoffice.com"})
    assert not d.allowed and "non-public" in d.reason


@pytest.mark.parametrize("bad", ["10.0.0.0/8", "169.254.169.254", "my tax.com", "-x.com", "", "mytaxoffice.com.attacker.net"])
def test_malformed_targets_refused(bad):
    assert not guard().check("check_tls", {"host": bad}).allowed


def test_unknown_tool_and_call_limit():
    g = guard()
    assert not g.check("run_shell", {"cmd": "ls"}).allowed
    for _ in range(3):
        assert g.check("check_email_auth", {"domain": "mytaxoffice.com"}).allowed
    assert not g.check("check_email_auth", {"domain": "mytaxoffice.com"}).allowed


def test_data_tools_take_no_arguments():
    assert guard().check("get_questionnaire_answers", {}).allowed
    assert not guard().check("get_questionnaire_answers", {"tenant_id": "other"}).allowed


def test_ip_helpers():
    assert not is_public_ip("10.1.2.3") and not is_public_ip("169.254.169.254")
    assert not is_public_ip("127.0.0.1") and is_public_ip("8.8.8.8")
    assert normalize_domain(" WWW.MyTaxOffice.com. ") == "www.mytaxoffice.com"
    with pytest.raises(ScopeError):
        normalize_domain("http://x.com")
