import base64
import io
import json
import os

import pyotp
import qrcode
import requests
from flask import Flask, Response, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from db import get_history, init_db, log_history
from tools import cert as cert_tool
from tools import crypt_tool, crypto_tools, jwt_tool, network, portcheck, webcheck
# --- константы вынесены FORGE refactor ---
CONST_5 = 5
CONST_60 = 60
CONST_200 = 200
CONST_400 = 400


app = Flask(__name__)
app.config["RATELIMIT_STORAGE_URI"] = "memory://"

limiter = Limiter(get_remote_address, app=app, default_limits=["120 per hour"])

HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")

init_db()
HIBP_BASE = "https://haveibeenpwned.com/api/v3"
PWNED_PASSWORDS_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "EgisStorm-Portfolio"

DEMO_BREACHES = [
    {
        "Name": "LinkedIn",
        "Title": "LinkedIn",
        "Domain": "linkedin.com",
        "BreachDate": "2021-06-22",
        "AddedDate": "2021-06-22T00:00:00Z",
        "PwnCount": 700000000,
        "Description": "Demo data: sample breach shown because no HIBP API key configured.",
        "DataClasses": ["Email addresses", "Passwords"],
        "IsVerified": True,
    },
    {
        "Name": "Adobe",
        "Title": "Adobe",
        "Domain": "adobe.com",
        "BreachDate": "2013-10-04",
        "AddedDate": "2013-11-04T00:00:00Z",
        "PwnCount": 152445165,
        "Description": "Demo data: sample breach shown because no HIBP API key configured.",
        "DataClasses": ["Email addresses", "Password hints", "Passwords"],
        "IsVerified": True,
    },
]


def hibp_email_lookup(email):
    if not HIBP_API_KEY:
        return {"mode": "demo", "breaches": DEMO_BREACHES, "error": None}
    try:
        resp = requests.get(
            f"{HIBP_BASE}/breachedaccount/{email}",
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": HIBP_API_KEY, "user-agent": USER_AGENT},
            timeout=10,
        )
        if resp.status_code == CONST_200:
            return {"mode": "live", "breaches": resp.json(), "error": None}
        if resp.status_code == 404:
            return {"mode": "live", "breaches": [], "error": None}
        if resp.status_code == 429:
            return {"mode": "error", "breaches": [], "error": "Rate limited by HIBP, try again later."}
        return {"mode": "error", "breaches": [], "error": f"HIBP returned {resp.status_code}"}
    except requests.RequestException as exc:
        return {"mode": "error", "breaches": [], "error": str(exc)}


def pwned_password_count(password):
    import hashlib

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:CONST_5], sha1[CONST_5:]
    try:
        resp = requests.get(f"{PWNED_PASSWORDS_URL}{prefix}", timeout=10)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            cand_suffix, count = line.split(":")
            if cand_suffix == suffix:
                return int(count)
        return 0
    except requests.RequestException:
        return None


def totp_pair():
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name="EgisStorm", issuer_name="EgisStorm")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return {
        "secret": secret,
        "uri": uri,
        "current_code": totp.now(),
        "qr_png": "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode(),
    }


def wireguard_pair():
    from nacl import bindings

    pk_bytes, sk_bytes = bindings.crypto_box_keypair()
    return base64.b64encode(sk_bytes).decode(), base64.b64encode(pk_bytes).decode()


def phone_info(number):
    import phonenumbers
    from phonenumbers import carrier, geocoder

    try:
        parsed = phonenumbers.parse(number, None)
    except phonenumbers.NumberParseException:
        return {"valid": False, "error": "Invalid phone number format."}

    valid = phonenumbers.is_valid_number(parsed)
    region = phonenumbers.region_code_for_number(parsed)
    country = geocoder.description_for_number(parsed, "ru") or geocoder.country_name_for_number(parsed)
    operator = carrier.name_for_number(parsed, "ru") or "unknown"
    return {
        "valid": valid,
        "possible": phonenumbers.is_possible_number(parsed),
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "country": country,
        "region": region,
        "operator": operator,
        "spam_lists": 0 if valid else None,
        "error": None,
    }


@app.before_request
def auth_guard():
    if not APP_PASSWORD:
        return
    if request.path.startswith("/static/"):
        return
    auth = request.authorization
    if auth and auth.username == "admin" and auth.password == APP_PASSWORD:
        return
    return Response(
        "Unauthorized",
        401,
        {"WWW-Authenticate": 'Basic realm="EgisStorm"'},
    )


@app.after_request
def log_api_calls(response):
    if request.path.startswith("/api/") and request.method == "POST":
        data = request.get_json(silent=True) or {}
        sanitized = {}
        for k, v in data.items():
            if k in ("password", "passphrase", "token"):
                sanitized[k] = "***"
            else:
                sanitized[k] = (v[:CONST_60] + "…") if isinstance(v, str) and len(v) > CONST_60 else v
        summary = response.status_code
        log_history(request.path.split("/")[-1], json.dumps(sanitized, ensure_ascii=False)[:CONST_200], summary)
    return response


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/email")
@limiter.limit("20 per minute")
def api_email():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return jsonify({"error": "Enter a valid email address."}), CONST_400
    result = hibp_email_lookup(email)
    result["email"] = email
    return jsonify(result)


@app.post("/api/password")
@limiter.limit("30 per minute")
def api_password():
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    if not password:
        return jsonify({"error": "Enter a password to check."}), CONST_400
    count = pwned_password_count(password)
    if count is None:
        return jsonify({"error": "Pwned Passwords service unavailable."}), 502
    strength = crypto_tools.password_strength(password)
    return jsonify(
        {
            "password_length": len(password),
            "pwned_count": count,
            "strength": strength,
            "tips": [
                "Используйте пароль длиннее 16 символов",
                "Никогда не повторяйте пароль между сайтами",
                "Включите 2FA (см. вкладку 2FA)",
            ],
        }
    )


@app.post("/api/generate-password")
def api_generate_password():
    data = request.get_json(silent=True) or {}
    length = min(64, max(8, int(data.get("length") or 20)))
    return jsonify(
        crypto_tools.generate_password(
            length,
            use_numbers=bool(data.get("numbers", True)),
            use_symbols=bool(data.get("symbols", True)),
            use_upper=bool(data.get("upper", True)),
        )
    )


@app.post("/api/phone")
def api_phone():
    data = request.get_json(silent=True) or {}
    number = (data.get("phone") or "").strip()
    if not number:
        return jsonify({"error": "Enter a phone number."}), CONST_400
    return jsonify(phone_info(number))


@app.post("/api/totp")
def api_totp():
    return jsonify(totp_pair())


@app.post("/api/wireguard")
def api_wireguard():
    data = request.get_json(silent=True) or {}
    server_pubkey = (data.get("server_pubkey") or "").strip()
    endpoint = (data.get("endpoint") or "").strip()
    if not server_pubkey or not endpoint:
        return jsonify({"error": "Нужен публичный ключ сервера и endpoint (например, vpn.example.com:51820)."}), CONST_400
    client_private, client_public = wireguard_pair()
    config = (
        "[Interface]\n"
        f"PrivateKey = {client_private}\n"
        "Address = 10.0.0.2/24\n"
        "DNS = 1.1.1.1\n\n"
        "[Peer]\n"
        f"PublicKey = {server_pubkey}\n"
        f"Endpoint = {endpoint}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = 25\n"
    )
    return jsonify({"client_private": client_private, "client_public": client_public, "config": config})


@app.post("/api/dns")
@limiter.limit("30 per minute")
def api_dns():
    data = request.get_json(silent=True) or {}
    host = (data.get("host") or "").strip()
    if not host:
        return jsonify({"error": "Введите домен."}), CONST_400
    return jsonify(network.dns_records(host))


@app.post("/api/whois")
@limiter.limit("30 per minute")
def api_whois():
    data = request.get_json(silent=True) or {}
    target = (data.get("domain") or "").strip()
    if not target:
        return jsonify({"error": "Введите домен."}), CONST_400
    return jsonify(network.rdap_lookup(target, "domain"))


@app.post("/api/ip")
@limiter.limit("30 per minute")
def api_ip():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "Введите IP-адрес."}), CONST_400
    return jsonify(network.ip_info(ip))


@app.post("/api/cert")
@limiter.limit("30 per minute")
def api_cert():
    data = request.get_json(silent=True) or {}
    host = (data.get("host") or "").strip()
    if not host:
        return jsonify({"error": "Введите хост."}), CONST_400
    return jsonify(cert_tool.ssl_cert_info(host))


@app.post("/api/headers")
@limiter.limit("30 per minute")
def api_headers():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Введите URL."}), CONST_400
    return jsonify(webcheck.security_headers(url))


@app.post("/api/hash")
def api_hash():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "")
    if not text:
        return jsonify({"error": "Введите текст."}), CONST_400
    hashes = crypto_tools.compute_hashes(text)
    return jsonify({"text": text, "hashes": hashes, "identify": crypto_tools.identify_hash(text.strip())})


@app.post("/api/b64")
def api_b64():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "")
    mode = data.get("mode") or "encode"
    if not text:
        return jsonify({"error": "Введите текст."}), CONST_400
    if mode == "encode":
        return jsonify({"result": crypto_tools.b64_encode(text), "mode": mode})
    decoded = crypto_tools.b64_decode(text)
    if decoded is None:
        return jsonify({"error": "Не валидный Base64."}), CONST_400
    return jsonify({"result": decoded, "mode": mode})


@app.post("/api/jwt")
def api_jwt():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"error": "Вставьте JWT-токен."}), CONST_400
    return jsonify(jwt_tool.jwt_decode(token))


@app.post("/api/urlcheck")
def api_urlcheck():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Введите URL."}), CONST_400
    return jsonify(webcheck.url_analysis(url))


@app.post("/api/ipwhois")
@limiter.limit("30 per minute")
def api_ipwhois():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "Введите IP-адрес."}), CONST_400
    return jsonify(network.rdap_lookup(ip, "ip"))


@app.post("/api/subnet")
def api_subnet():
    data = request.get_json(silent=True) or {}
    cidr = (data.get("cidr") or "").strip()
    if not cidr:
        return jsonify({"error": "Введите сеть в формате CIDR (например, 192.168.1.0/24)."}), CONST_400
    return jsonify(network.subnet_calc(cidr))


@app.post("/api/expand")
@limiter.limit("30 per minute")
def api_expand():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Введите ссылку."}), CONST_400
    return jsonify(webcheck.expand_url(url))


@app.post("/api/mxcheck")
@limiter.limit("30 per minute")
def api_mxcheck():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    if not email or "@" not in email:
        return jsonify({"error": "Введите корректный email."}), CONST_400
    return jsonify(network.mx_check(email))


@app.post("/api/cve")
@limiter.limit("30 per minute")
def api_cve():
    data = request.get_json(silent=True) or {}
    query = (data.get("query") or "").strip()
    if not query:
        return jsonify({"error": "Введите название продукта (например, openssh 9.0)."}), CONST_400
    return jsonify(network.cve_search(query))


@app.post("/api/portcheck")
@limiter.limit("30 per minute")
def api_portcheck():
    data = request.get_json(silent=True) or {}
    host = (data.get("host") or "").strip()
    if not host:
        return jsonify({"error": "Введите хост."}), CONST_400
    if data.get("common"):
        return jsonify(portcheck.common_ports_scan(host))
    port = (data.get("port") or "").strip()
    if not port:
        return jsonify({"error": "Укажите порт или включите проверку общих портов."}), CONST_400
    return jsonify(portcheck.tcp_check(host, port))


@app.post("/api/robots")
@limiter.limit("30 per minute")
def api_robots():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Введите URL."}), CONST_400
    return jsonify(portcheck.robots_txt(url))


@app.post("/api/crypt")
def api_crypt():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    passphrase = (data.get("passphrase") or "").strip()
    mode = (data.get("mode") or "encrypt")
    if not text:
        return jsonify({"error": "Введите текст."}), CONST_400
    if not passphrase:
        return jsonify({"error": "Введите пароль-ключ."}), CONST_400
    if mode == "encrypt":
        return jsonify({"result": crypt_tool.aes_encrypt(text, passphrase), "mode": mode, "algo": "AES-256-CBC + PKCS7"})
    result = crypt_tool.aes_decrypt(text, passphrase)
    if "error" in result:
        return jsonify(result), CONST_400
    return jsonify({"result": result["text"], "mode": mode, "algo": "AES-256-CBC + PKCS7"})


@app.post("/api/myip")
def api_myip():
    ip = request.remote_addr or "127.0.0.1"
    info = network.ip_info(ip)
    if "error" in info:
        return jsonify({"ip": ip, "note": "Внешняя геолокация недоступна, но ваш адрес: " + ip})
    info["note"] = "Ваш внешний адрес"
    return jsonify(info)


@app.get("/api/history")
def api_history():
    return jsonify({"items": get_history(50)})


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False, port=5000)