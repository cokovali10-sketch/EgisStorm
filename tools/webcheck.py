from urllib.parse import urljoin, urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS принудительно включает HTTPS. Отсутствует → риск понижения до HTTP.",
    "Content-Security-Policy": "CSP ограничивает источники загрузки контента. Отсутствует → риск XSS.",
    "X-Frame-Options": "Защита от clickjacking. Отсутствует → сайт можно встроить в iframe.",
    "X-Content-Type-Options": "Блокирует MIME-сниффинг. Отсутствует → риск подмены контента.",
    "Referrer-Policy": "Контролирует передачу Referer. Отсутствует → возможна утечка URL.",
    "Permissions-Policy": "Ограничивает доступ к камере/микрофону и т.д. Отсутствует → лишние права.",
    "X-XSS-Protection": "Устаревшая, но часто ожидаемая защита от отражённого XSS.",
}

SUSPICIOUS_TLDS = {"zip", "mov", "work", "click", "country", "gq", "tk", "ml", "cf", "ga", "xyz", "top", "icu"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "rb.gy", "cutt.ly", "t.ly", "su.pr", "ow.ly"}


def security_headers(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        resp = requests.get(url, timeout=12, allow_redirects=True, headers={"User-Agent": "EgisStorm/1.0"})
    except requests.RequestException as exc:
        return {"error": str(exc)}

    headers = {k.lower(): v for k, v in resp.headers.items()}
    checks = []
    for header, advice in SECURITY_HEADERS.items():
        present = header.lower() in headers
        checks.append(
            {
                "header": header,
                "present": present,
                "value": headers.get(header.lower(), ""),
                "advice": advice,
            }
        )
    return {
        "url": url,
        "final_url": resp.url,
        "status": resp.status_code,
        "server": headers.get("server", "—"),
        "redirects": len(resp.history),
        "checks": checks,
        "score": round(100 * sum(1 for c in checks if c["present"]) / len(checks)),
    }


def url_analysis(url):
    url = url.strip()
    parsed = urlparse(url if "://" in url else "//" + url)
    host = (parsed.hostname or "").lower()
    flags = []

    if parsed.scheme != "https":
        flags.append({"severity": "bad", "text": "Схема не HTTPS — данные передаются открыто."})
    else:
        flags.append({"severity": "good", "text": "Используется HTTPS."})

    try:
        import ipaddress

        ipaddress.ip_address(host)
        flags.append({"severity": "bad", "text": "Хост — IP-адрес, а не домен (типично для фишинга)."})
    except ValueError:
        pass

    if "@" in parsed.path or "@" in (parsed.netloc):
        flags.append({"severity": "bad", "text": "Символ @ — может скрывать реальный домен."})

    if host.startswith("xn--") or "xn--" in host:
        flags.append({"severity": "warn", "text": "Punycode (xn--) — возможна подмена символов."})

    if any(ord(ch) > 127 for ch in host):
        flags.append({"severity": "warn", "text": "Не-ASCII символы в домене — риск омоглиф-атаки."})

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append({"severity": "warn", "text": f"TLD .{tld} часто используется в вредоносных кампаниях."})

    base = host
    if base in SHORTENERS or any(base.endswith("." + s) for s in SHORTENERS):
        flags.append({"severity": "warn", "text": "Сокращатель ссылок — реальный адрес скрыт."})

    if parsed.port and parsed.port not in (80, 443):
        flags.append({"severity": "warn", "text": f"Нестандартный порт {parsed.port}."})

    if parsed.username or parsed.password:
        flags.append({"severity": "bad", "text": "URL содержит логин/пароль."})

    if not flags:
        flags.append({"severity": "good", "text": "Явных признаков фишинга не обнаружено."})

    return {"url": url, "scheme": parsed.scheme, "host": host, "path": parsed.path, "flags": flags}


def expand_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    chain = []
    current = url
    try:
        for _ in range(8):
            resp = requests.get(
                current,
                allow_redirects=False,
                timeout=10,
                headers={"User-Agent": "EgisStorm/1.0"},
            )
            location = resp.headers.get("Location", "")
            chain.append({"url": current, "status": resp.status_code, "location": location})
            if resp.status_code in (301, 302, 303, 307, 308) and location:
                current = urljoin(current, location)
                continue
            break
        return {"start": url, "chain": chain, "final": chain[-1]["url"], "hops": len(chain) - 1}
    except requests.RequestException as exc:
        return {"error": str(exc)}