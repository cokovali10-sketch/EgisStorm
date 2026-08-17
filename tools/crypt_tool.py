import base64
import os

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _key_from(passphrase):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(passphrase.encode("utf-8"))
    return digest.finalize()


def aes_encrypt(text, passphrase):
    key = _key_from(passphrase)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(text.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()


def aes_decrypt(data_b64, passphrase):
    try:
        raw = base64.b64decode(data_b64)
    except Exception:
        return {"error": "Некорректный Base64."}
    if len(raw) < 32:
        return {"error": "Данные слишком короткие."}
    key = _key_from(passphrase)
    iv, ct = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded) + unpadder.finalize()
        return {"text": plain.decode("utf-8")}
    except Exception:
        return {"error": "Неверный пароль или данные повреждены."}