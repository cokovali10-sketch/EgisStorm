import ipaddress
import socket

import dns.resolver
import requests

RDAP_DOMAIN = "https://rdap.org/domain/"
RDAP_IP = "https://rdap.org/ip/"
IPINFO = "https://ipwho.is/"

DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com",
    "yopmail.com", "trashmail.com", "dispostable.com", "maildrop.cc",
    "throwawaymail.com", "temp-mail.org", "sharklasers.com", "mailnesia.com",
}


def dns_records(host):
    host = host.strip()
    if not host:
        return {"error": "Введите домен."}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 6
    records = {}
    for rtype in ("A", "AAAA", "CNAME", "NS", "MX", "TXT"):
        try:
            answers = resolver.resolve(host, rtype)
            values = []
            for a in answers:
                if rtype == "MX":
                    values.append(f"{a.preference} → {a.exchange}")
                elif rtype == "TXT":
                    values.append("".join(part.decode() for part in a.strings))
                else:
                    values.append(str(a))
            records[rtype] = values
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            records[rtype] = None
    return {"host": host, "records": records}


def rdap_lookup(target, kind="domain"):
    url = (RDAP_DOMAIN if kind == "domain" else RDAP_IP) + target
    try:
        resp = requests.get(url, timeout=10, headers={"Accept": "application/rdap+json"})
        if resp.status_code == 404:
            return {"error": f"Объект {target} не найден в RDAP."}
        if resp.status_code != 200:
            return {"error": f"RDAP ответил {resp.status_code}."}
        data = resp.json()
    except requests.RequestException as exc:
        return {"error": str(exc)}

    events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}
    result = {
        "target": target,
        "handle": data.get("handle", "—"),
        "status": data.get("status", []),
        "registrar": (data.get("entities") or [{}])[0].get("vcardArray", [[], []])[1][0][3] if data.get("entities") else "—",
        "created": events.get("registration"),
        "updated": events.get("last changed"),
        "expires": events.get("expiration"),
        "nameservers": [ns.get("ldhName", "") for ns in data.get("nameservers", [])],
    }
    if kind == "ip":
        result["network"] = f"{data.get('startAddress')} – {data.get('endAddress')}"
        result["ip_version"] = data.get("ipVersion")
        result["country"] = data.get("country")
    return result


def ip_info(ip):
    ip = ip.strip()
    try:
        resp = requests.get(IPINFO + ip, timeout=10)
        data = resp.json() if resp.ok else {"success": False, "message": f"HTTP {resp.status_code}"}
    except requests.RequestException as exc:
        return {"error": str(exc)}

    rdns = None
    try:
        rdns = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        pass

    if not data.get("success"):
        return {"error": data.get("message", "Не удалось определить.")}

    return {
        "ip": data.get("ip"),
        "type": data.get("type"),
        "country": data.get("country"),
        "region": data.get("region"),
        "city": data.get("city"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "org": data.get("connection", {}).get("org"),
        "isp": data.get("connection", {}).get("isp"),
        "asn": data.get("connection", {}).get("asn"),
        "timezone": data.get("timezone", {}).get("id"),
        "reverse_dns": rdns,
    }


def subnet_calc(cidr):
    cidr = cidr.strip()
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        return {"error": f"Неверный CIDR: {exc}"}
    usable = max(0, net.num_addresses - 2)
    if usable > 0:
        first = net.network_address + 1
        last = net.broadcast_address - 1
    else:
        first = last = None
    result = {
        "cidr": str(net),
        "version": f"IPv{net.version}",
        "network": str(net.network_address),
        "prefix": net.prefixlen,
        "total_addresses": net.num_addresses,
        "usable_hosts": usable,
        "first_usable": str(first) if first is not None else None,
        "last_usable": str(last) if last is not None else None,
    }
    if net.version == 4:
        result["netmask"] = str(net.netmask)
        result["broadcast"] = str(net.broadcast_address)
        result["classful"] = ("A" if net.prefixlen <= 8 else "B" if net.prefixlen <= 16 else "C" if net.prefixlen <= 24 else "D/E")
    return result


def mx_check(email):
    domain = (email.split("@")[-1] or "").strip().lower()
    if not domain or "." not in domain:
        return {"error": "Некорректный email."}
    disposable = domain in DISPOSABLE_DOMAINS
    mx = []
    has_a = False
    try:
        ans = dns.resolver.resolve(domain, "MX", lifetime=6)
        mx = [f"{r.preference} → {r.exchange}" for r in ans]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
        mx = []
    try:
        has_a = bool(dns.resolver.resolve(domain, "A", lifetime=6))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
        has_a = False
    return {
        "email": email,
        "domain": domain,
        "mx": mx,
        "has_mx": bool(mx),
        "has_a": has_a,
        "disposable": disposable,
        "disposable_hit": next((d for d in DISPOSABLE_DOMAINS if d == domain), None),
    }


def cve_search(query):
    import json
    from urllib.parse import quote

    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": query, "resultsPerPage": 20},
            timeout=20,
        )
        if resp.status_code != 200:
            return {"error": f"NVD API вернул {resp.status_code}."}
        data = resp.json()
    except requests.RequestException as exc:
        return {"error": str(exc)}

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cvss = None
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(k)
            if metrics:
                cvss = metrics[0].get("cvssData", {}).get("baseScore") or metrics[0].get("baseScore")
                break
        desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "—")
        results.append(
            {
                "id": cve.get("id"),
                "cvss": cvss,
                "published": str(cve.get("published") or "")[:10],
                "summary": desc[:240],
                "refs": [r.get("url") for r in cve.get("references", [])][:3],
            }
        )
    return {"query": query, "count": data.get("totalResults", 0), "results": results}