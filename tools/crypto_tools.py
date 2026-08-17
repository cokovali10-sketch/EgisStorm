import math
import re
import secrets
import string
import base64
import hashlib

HASH_ALGORITHMS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512"]

POOLS = [
    (string.ascii_lowercase, r"[a-z]"),
    (string.ascii_uppercase, r"[A-Z]"),
    (string.digits, r"\d"),
    (string.punctuation, r"[^a-zA-Z0-9]"),
]


def password_strength(password):
    present = [pool for pool, pattern in POOLS if re.search(pattern, password)]
    if not password:
        entropy = 0.0
        label = "пустой"
    elif not present:
        entropy = 0.0
        label = "слабый"
    else:
        space = sum(len(p) for p, _ in POOLS if p in present)
        entropy = len(password) * math.log2(space)
        if len(password) < 8:
            label = "слабый"
        elif entropy < 45:
            label = "средний"
        elif entropy < 70:
            label = "хороший"
        else:
            label = "сильный"
    return {"entropy": round(entropy, 1), "score": label, "length": len(password)}


def generate_password(length=20, use_numbers=True, use_symbols=True, use_upper=True):
    pool = string.ascii_lowercase
    if use_upper:
        pool += string.ascii_uppercase
    if use_numbers:
        pool += string.digits
    if use_symbols:
        pool += string.punctuation
    password = "".join(secrets.choice(pool) for _ in range(length))
    return {
        "password": password,
        "length": len(password),
        "entropy": password_strength(password)["entropy"],
        "score": password_strength(password)["score"],
    }


def compute_hashes(text, algorithms=None):
    algos = algorithms or HASH_ALGORITHMS
    return {alg: hashlib.new(alg, text.encode("utf-8")).hexdigest() for alg in algos}


def identify_hash(hex_str):
    length = len(hex_str.strip())
    mapping = {
        32: "MD5",
        40: "SHA-1",
        56: "SHA-224",
        64: "SHA-256",
        96: "SHA-384",
        128: "SHA-512",
    }
    guess = mapping.get(length)
    if guess:
        return {"guess": guess, "note": "Проверьте: длина совпадает с хешем " + guess + "."}
    if re.fullmatch(r"[0-9a-fA-F]{32,}", hex_str.strip()):
        return {"guess": "SHA-family / произвольный hex", "note": "Точный алгоритм по длине не определяется."}
    return {"guess": None, "note": "Не похоже на hex-хеш."}


def b64_encode(text):
    return base64.b64encode(text.encode("utf-8")).decode()


def b64_decode(text):
    try:
        padded = text.strip() + "=" * (-len(text.strip()) % 4)
        return base64.b64decode(padded).decode("utf-8")
    except Exception:
        return None


def b64url_decode(seg):
    padded = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(padded).decode("utf-8", "replace")