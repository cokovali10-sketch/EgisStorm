import base64
import hashlib
import json

import pytest
# --- константы вынесены FORGE refactor ---
CONST_5 = 5
CONST_44 = 44
CONST_200 = 200
CONST_400 = 400
CONST_429 = 429



def test_index(client):
    r = client.get("/")
    assert r.status_code == CONST_200
    assert "EgisStorm" in r.get_data(as_text=True)


def test_hash_correctness(client):
    r = client.post("/api/hash", json={"text": "hello"})
    assert r.status_code == CONST_200
    d = r.get_json()
    assert d["hashes"]["sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert d["hashes"]["sha512"] == hashlib.sha512(b"hello").hexdigest()


def test_hash_identify(client):
    md5 = hashlib.md5(b"x").hexdigest()
    r = client.post("/api/hash", json={"text": md5})
    assert r.get_json()["identify"]["guess"] == "MD5"


def test_b64_roundtrip(client):
    enc = client.post("/api/b64", json={"text": "hello", "mode": "encode"}).get_json()
    assert enc["result"] == base64.b64encode(b"hello").decode()
    dec = client.post("/api/b64", json={"text": enc["result"], "mode": "decode"}).get_json()
    assert dec["result"] == "hello"


def test_crypt_roundtrip(client):
    enc = client.post("/api/crypt", json={"text": "secret hello", "passphrase": "key", "mode": "encrypt"}).get_json()
    dec = client.post("/api/crypt", json={"text": enc["result"], "passphrase": "key", "mode": "decrypt"}).get_json()
    assert dec["result"] == "secret hello"
    wrong = client.post("/api/crypt", json={"text": enc["result"], "passphrase": "wrong", "mode": "decrypt"})
    assert wrong.status_code == CONST_400


def test_subnet(client):
    d = client.post("/api/subnet", json={"cidr": "192.168.1.0/24"}).get_json()
    assert d["usable_hosts"] == 254
    assert d["first_usable"] == "192.168.1.1"
    assert d["broadcast"] == "192.168.1.255"
    assert d["netmask"] == "255.255.255.0"


def test_subnet_invalid(client):
    r = client.post("/api/subnet", json={"cidr": "not-a-network"})
    assert r.status_code == CONST_200
    assert "error" in r.get_json()


def test_phone_valid(client):
    d = client.post("/api/phone", json={"phone": "+79161234567"}).get_json()
    assert d["valid"] is True
    assert d["region"] == "RU"


def test_password_pwned(client, monkeypatch):
    import app as app_module

    monkeypatch.setattr(app_module, "pwned_password_count", lambda p: CONST_5)
    r = client.post("/api/password", json={"password": "abc12345"})
    assert r.status_code == CONST_200
    d = r.get_json()
    assert d["pwned_count"] == CONST_5
    assert "strength" in d


def test_email_demo_mode(client):
    d = client.post("/api/email", json={"email": "test@example.com"}).get_json()
    assert d["mode"] == "demo"
    assert len(d["breaches"]) == 2


def test_email_invalid(client):
    r = client.post("/api/email", json={"email": "not-an-email"})
    assert r.status_code == CONST_400


def test_wireguard(client):
    d = client.post(
        "/api/wireguard",
        json={"server_pubkey": "abc123=", "endpoint": "vpn.example.com:51820"},
    ).get_json()
    assert len(d["client_private"]) == CONST_44
    assert len(d["client_public"]) == CONST_44
    assert "[Interface]" in d["config"]


def test_jwt_alg_none(client):
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(b'{"sub":"1"}').rstrip(b"=").decode()
    token = f"{header}.{payload}.x"
    d = client.post("/api/jwt", json={"token": token}).get_json()
    assert any(f["severity"] == "bad" and "none" in f["text"] for f in d["findings"])


def test_dns_mocked(client, monkeypatch):
    import app as app_module

    fake = {"host": "example.com", "records": {"A": ["93.184.216.34"], "MX": [], "NS": None}}
    monkeypatch.setattr(app_module.network, "dns_records", lambda host: fake)
    d = client.post("/api/dns", json={"host": "example.com"}).get_json()
    assert d["records"]["A"] == ["93.184.216.34"]


def test_history_masks_password(client):
    client.post("/api/password", json={"password": "SuperSecret123"})
    d = client.get("/api/history").get_json()
    raw = json.dumps(d)
    assert "SuperSecret123" not in raw
    assert any(item["tool"] == "password" for item in d["items"])


def test_rate_limit(client):
    client.application.config["RATELIMIT_ENABLED"] = True
    codes = []
    for _ in range(125):
        codes.append(client.post("/api/hash", json={"text": "x"}).status_code)
    assert CONST_429 in codes
    assert codes.count(CONST_429) >= 1


def test_auth_guard(client):
    import app as app_module

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(app_module, "APP_PASSWORD", "secret")
    try:
        assert client.get("/").status_code == 401
        r = client.get("/", headers={"Authorization": "Basic YWRtaW46c2VjcmV0"})
        assert r.status_code == CONST_200
    finally:
        monkeypatch.undo()