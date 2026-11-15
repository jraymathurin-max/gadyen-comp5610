"""TLS checks using only the Python standard library.
(For a deeper cipher-by-cipher analysis, add sslyze in a later phase.)"""
import socket
import ssl
import time


def _accepts_version(host: str, port: int, version, timeout: float):
    """True/False if the server accepts this TLS version; None if this machine
    cannot test it (local OpenSSL refuses old protocols)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLError as exc:
        text = str(exc).upper()
        local_refusal = "NO_PROTOCOLS_AVAILABLE" in text or (
            "UNSUPPORTED_PROTOCOL" in text and "ALERT" not in text)
        if local_refusal:
            return None  # cannot tell from this machine
        return False
        return False
    except OSError:
        return False


def check_tls(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    result = {"host": host, "port": port, "reachable": True}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                result["protocol"] = tls.version()
                expires = ssl.cert_time_to_seconds(cert["notAfter"])
                result["cert_valid"] = True
                result["days_until_expiry"] = int((expires - time.time()) // 86400)
    except ssl.SSLCertVerificationError as exc:
        result["cert_valid"] = False
        result["error"] = getattr(exc, "verify_message", str(exc))
    except OSError as exc:
        result["reachable"] = False
        result["error"] = str(exc)[:200]
        return result
    result["accepts_tls1_0"] = _accepts_version(host, port, ssl.TLSVersion.TLSv1, timeout)
    result["accepts_tls1_1"] = _accepts_version(host, port, ssl.TLSVersion.TLSv1_1, timeout)
    return result
