import socket

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP-submission",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt", 27017: "MongoDB",
}


def tcp_check(host, port, timeout=3):
    host = host.strip().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {"host": host, "port": int(port), "open": True}
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return {"host": host, "port": int(port), "open": False, "reason": str(exc)}


def common_ports_scan(host, timeout=2):
    results = []
    for port, service in COMMON_PORTS.items():
        try:
            with socket.create_connection((host, port), timeout=timeout):
                results.append({"port": port, "service": service, "open": True})
        except (socket.timeout, ConnectionRefusedError, OSError):
            results.append({"port": port, "service": service, "open": False})
    return {"host": host, "results": results}


def robots_txt(url):
    from urllib.parse import urljoin, urlparse

    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    try:
        import requests

        resp = requests.get(
            urljoin(base, "/robots.txt"), timeout=10, headers={"User-Agent": "EgisStorm/1.0"}
        )
        body = resp.text if resp.status_code == 200 else ""
    except Exception as exc:
        return {"error": str(exc), "base": base}

    groups = []
    sitemaps = []
    current = None
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "user-agent":
            current = {"agent": value, "allow": [], "disallow": []}
            groups.append(current)
        elif key == "allow" and current:
            current["allow"].append(value)
        elif key == "disallow" and current:
            current["disallow"].append(value)
        elif key == "sitemap":
            sitemaps.append(value)
    return {
        "base": base,
        "status": resp.status_code,
        "groups": groups,
        "sitemaps": sitemaps,
        "raw": body[:3000],
        "blocked_paths": [g for g in groups if g["agent"].lower() == "*"],
    }