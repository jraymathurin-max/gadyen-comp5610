"""Checks a SHORT, FIXED list of risky ports with a plain TCP connect.
No port ranges and no arguments from the LLM other than the host."""
import socket

RISKY_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MS-SQL", 3306: "MySQL",
               3389: "RDP (Remote Desktop)", 5900: "VNC"}


def check_exposed_services(host: str, timeout: float = 3.0) -> dict:
    open_ports = []
    for port, name in RISKY_PORTS.items():
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append({"port": port, "service": name})
        except OSError:
            pass
    return {"host": host, "ports_checked": sorted(RISKY_PORTS), "open": open_ports}
