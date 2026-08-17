import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def ssl_cert_info(host, port=443):
    host = host.strip().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                proto = ssock.version()
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception as exc:
        return {"error": f"Не удалось получить сертификат: {exc}"}

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    not_before = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    not_after = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    days_left = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days

    sans = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    return {
        "host": host,
        "port": port,
        "subject": subject,
        "issuer": issuer,
        "serial": format(cert.serial_number, "x").upper(),
        "version": cert.version.name,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "not_before": not_before,
        "not_after": not_after,
        "days_left": days_left,
        "san": sans[:50],
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex().upper(),
        "tls_version": proto,
        "cipher": f"{cipher[0]} ({cipher[2]} бит)",
        "expired": days_left < 0,
        "expires_soon": 0 <= days_left <= 30,
    }