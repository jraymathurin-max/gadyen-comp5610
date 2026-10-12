"""HTTP security header checks. Redirects are NOT followed automatically, so a
malicious site cannot bounce the scanner to an internal address."""
import re

import httpx

GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{0,100})',
                          re.IGNORECASE)


def check_http_headers(host: str, timeout: float = 10.0) -> dict:
    result = {"host": host}
    with httpx.Client(follow_redirects=False, timeout=timeout) as client:
        try:
            resp = client.get(f"https://{host}/")
        except httpx.HTTPError as exc:
            return {"host": host, "reachable": False, "error": str(exc)[:200]}
        headers = {k.lower(): v[:300] for k, v in resp.headers.items()}
        body = resp.text[:200_000] if "text/html" in headers.get("content-type", "") else ""
        match = GENERATOR_RE.search(body)
        result.update({
            "reachable": True,
            "status": resp.status_code,
            "hsts": headers.get("strict-transport-security"),
            "csp": headers.get("content-security-policy"),
            "x_frame_options": headers.get("x-frame-options"),
            "x_content_type_options": headers.get("x-content-type-options"),
            "server": headers.get("server"),
            "x_powered_by": headers.get("x-powered-by"),
            "generator": match.group(1) if match else None,
        })
        try:
            plain = client.get(f"http://{host}/")
            location = plain.headers.get("location", "")
            result["http_redirects_to_https"] = (plain.status_code in (301, 302, 307, 308)
                                                 and location.lower().startswith("https://"))
        except httpx.HTTPError:
            result["http_redirects_to_https"] = None  # port 80 closed is acceptable
    return result
