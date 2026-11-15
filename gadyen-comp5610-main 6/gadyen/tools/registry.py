"""Tool catalog given to the LLM (JSON schemas) and the dispatcher that runs them.
The LLM never chooses the tenant: data tools are bound to the tenant by the agent."""
import concurrent.futures

from . import dns_tools, http_tools, port_tools, tls_tools

HOST_SCHEMA = {"type": "string", "maxLength": 253, "pattern": "^[A-Za-z0-9.-]+$"}

TOOL_SCHEMAS = [
    {
        "name": "check_email_auth",
        "description": "Check SPF, DKIM and DMARC email-authentication records for a VERIFIED "
                       "domain of this practice. Passive DNS lookup.",
        "input_schema": {"type": "object", "properties": {
            "domain": HOST_SCHEMA,
            "dkim_selectors": {"type": "array", "items": {"type": "string", "maxLength": 63},
                               "maxItems": 8}},
            "required": ["domain"], "additionalProperties": False},
    },
    {
        "name": "check_tls",
        "description": "Check the HTTPS certificate and old TLS versions on a host that belongs "
                       "to a VERIFIED domain.",
        "input_schema": {"type": "object", "properties": {"host": HOST_SCHEMA},
                         "required": ["host"], "additionalProperties": False},
    },
    {
        "name": "check_http_headers",
        "description": "Check HTTP security headers, HTTP-to-HTTPS redirect and version "
                       "disclosure on the website of a VERIFIED domain.",
        "input_schema": {"type": "object", "properties": {"host": HOST_SCHEMA},
                         "required": ["host"], "additionalProperties": False},
    },
    {
        "name": "check_exposed_services",
        "description": "Check whether risky services (RDP, SMB, FTP, Telnet, VNC, databases) "
                       "are reachable from the Internet on a host of a VERIFIED domain.",
        "input_schema": {"type": "object", "properties": {"host": HOST_SCHEMA},
                         "required": ["host"], "additionalProperties": False},
    },
    {
        "name": "get_questionnaire_answers",
        "description": "Read this practice's onboarding questionnaire answers.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "get_endpoint_reports",
        "description": "Read the computer self-check reports uploaded by this practice.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]

TOOL_NAMES = {t["name"] for t in TOOL_SCHEMAS}

NETWORK_TOOLS = {
    "check_email_auth": lambda a: dns_tools.check_email_auth(a["domain"], a.get("dkim_selectors")),
    "check_tls": lambda a: tls_tools.check_tls(a["host"]),
    "check_http_headers": lambda a: http_tools.check_http_headers(a["host"]),
    "check_exposed_services": lambda a: port_tools.check_exposed_services(a["host"]),
}

_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=4)


def run_network_tool(name: str, args: dict, timeout: float = 45.0) -> dict:
    """Run a network tool with a hard timeout."""
    future = _POOL.submit(NETWORK_TOOLS[name], args)
    return future.result(timeout=timeout)
