import json

from tools.crypto_tools import b64url_decode


def jwt_decode(token):
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "JWT должен состоять из 3 частей (header.payload.signature)."}
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception as exc:
        return {"error": f"Не удалось декодировать: {exc}"}

    alg = header.get("alg", "")
    findings = []
    if alg == "none":
        findings.append({"severity": "bad", "text": "alg=none — токен не подписан. Критическая уязвимость."})
    elif alg.startswith("HS"):
        findings.append({"severity": "info", "text": "Симметричный алгоритм (HS). Секрет должен быть длинным."})
    elif alg.startswith(("RS", "ES", "PS")):
        findings.append({"severity": "info", "text": "Асимметричная подпись (публичный ключ для проверки)."})

    now = __import__("time").time()
    exp = payload.get("exp")
    nbf = payload.get("nbf")
    if exp:
        if exp < now:
            findings.append({"severity": "bad", "text": "Токен истёк (exp)."})
        else:
            findings.append({"severity": "info", "text": f"Действителен до {exp}."})
    else:
        findings.append({"severity": "warn", "text": "Нет поля exp — токен не имеет срока жизни."})
    if nbf and nbf > now:
        findings.append({"severity": "warn", "text": "Токен ещё не активен (nbf)."})

    return {
        "header": header,
        "payload": payload,
        "signature": parts[2],
        "signature_hex_length": len(parts[2]) * 3 // 4,
        "findings": findings,
    }