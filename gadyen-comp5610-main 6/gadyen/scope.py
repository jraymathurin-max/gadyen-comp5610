"""Scope enforcement and the policy guard.

Every tool call proposed by the LLM passes through PolicyGuard.check() BEFORE it runs.
The guard never trusts the model: it re-validates the tool name, the arguments,
the target domain (must belong to a VERIFIED domain of this tenant) and, for active
checks, that the host resolves only to public Internet addresses.
"""
import ipaddress
import re
import socket
from dataclasses import dataclass, field

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$")

# Tools that open network connections to the client's servers.
ACTIVE_TOOLS = {"check_tls", "check_http_headers", "check_exposed_services"}
# Tools that only read public DNS data.
PASSIVE_DOMAIN_TOOLS = {"check_email_auth"}
# Tools that only read this tenant's own stored data (no target).
DATA_TOOLS = {"get_questionnaire_answers", "get_endpoint_reports"}


class ScopeError(ValueError):
    """Raised when a target is outside the allowed scope."""


def normalize_domain(value: str) -> str:
    domain = str(value).strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        raise ScopeError(f"invalid domain name: {value!r}")
    return domain


def is_public_ip(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_global


def resolve_public_ips(host: str) -> list:
    """Resolve host and require EVERY address to be public (blocks SSRF to 127.0.0.1,
    10.x, 192.168.x, 169.254.169.254 cloud metadata, etc.)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ScopeError(f"cannot resolve {host}: {exc}") from exc
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise ScopeError(f"no address for {host}")
    bad = [ip for ip in ips if not is_public_ip(ip)]
    if bad:
        raise ScopeError(f"{host} resolves to non-public address(es) {bad}")
    return ips


def in_verified_scope(domain: str, verified: set) -> bool:
    return any(domain == v or domain.endswith("." + v) for v in verified)


@dataclass
class Decision:
    allowed: bool
    reason: str = ""


@dataclass
class PolicyGuard:
    verified_domains: set
    allowed_tools: set
    max_calls_per_tool: int = 10
    resolver: object = resolve_public_ips  # injectable for tests
    _counts: dict = field(default_factory=dict)

    def check(self, tool_name: str, args: dict) -> Decision:
        if tool_name not in self.allowed_tools:
            return Decision(False, f"tool '{tool_name}' is not allowed")
        if not isinstance(args, dict):
            return Decision(False, "arguments must be an object")
        count = self._counts.get(tool_name, 0)
        if count >= self.max_calls_per_tool:
            return Decision(False, f"call limit reached for {tool_name}")

        if tool_name in DATA_TOOLS:
            if args:
                return Decision(False, "this tool takes no arguments")
        else:
            target = args.get("domain") or args.get("host")
            if not target:
                return Decision(False, "missing target")
            try:
                domain = normalize_domain(target)
            except ScopeError as exc:
                return Decision(False, str(exc))
            if not in_verified_scope(domain, self.verified_domains):
                return Decision(False, f"{domain} is not a verified domain of this practice")
            if tool_name in ACTIVE_TOOLS:
                try:
                    self.resolver(domain)
                except ScopeError as exc:
                    return Decision(False, str(exc))

        self._counts[tool_name] = count + 1
        return Decision(True)
