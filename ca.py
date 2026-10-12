"""Local root CA + per-hostname leaf certificate generation.

Lets the proxy transparently impersonate any domain the browser visits: the
root CA is generated once and installed into the browser/OS trust store, and
a short-lived leaf certificate is minted (and cached) on demand for whatever
hostname is being intercepted.
"""

import datetime
import ipaddress
import threading
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT_CA_COMMON_NAME = "PQC Proxy Local Root CA (do not trust outside your own machine)"
LEAF_VALIDITY_DAYS = 7
_LEAF_RENEWAL_MARGIN = datetime.timedelta(hours=1)

_leaf_cache: dict[tuple[str, bytes], tuple[str, str]] = {}
_leaf_cache_lock = threading.Lock()


def ensure_root_ca(ca_dir="ca"):
    """Load the local root CA, generating it on first run."""
    ca_dir = Path(ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)
    key_path = ca_dir / "root-ca.key"
    cert_path = ca_dir / "root-ca.crt"

    if key_path.exists() and cert_path.exists():
        ca_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return ca_key, ca_cert, key_path, cert_path

    ca_key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ROOT_CA_COMMON_NAME)])
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA384())
    )

    key_path.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Generated new root CA at {cert_path}")
    print("[+] Install this certificate into your browser/OS trust store to avoid certificate warnings.")

    return ca_key, ca_cert, key_path, cert_path


def get_leaf_cert(hostname, ca_key, ca_cert, cache_dir="ca/leaves"):
    """Return (key_path, cert_path) for a leaf certificate covering `hostname`,
    generating and caching one if needed.

    Cache entries (both in-memory and on-disk) are keyed/validated against the
    calling CA's fingerprint, not just the hostname -- otherwise a leaf cached
    under a previous or rotated root CA would get served again and fail
    signature verification against the current one.
    """
    ca_fingerprint = ca_cert.fingerprint(hashes.SHA256())
    cache_key = (hostname, ca_fingerprint)

    with _leaf_cache_lock:
        cached = _leaf_cache.get(cache_key)
    if cached and Path(cached[0]).exists() and Path(cached[1]).exists():
        return cached

    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    key_path = cache_dir / f"{hostname}.key"
    cert_path = cache_dir / f"{hostname}.crt"

    if key_path.exists() and cert_path.exists():
        existing_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        still_valid = (
            existing_cert.not_valid_after_utc
            > datetime.datetime.now(datetime.timezone.utc) + _LEAF_RENEWAL_MARGIN
        )
        if still_valid:
            try:
                existing_cert.verify_directly_issued_by(ca_cert)
            except (InvalidSignature, ValueError, TypeError):
                still_valid = False  # signed by a different/rotated CA -- regenerate below
        if still_valid:
            result = (str(key_path), str(cert_path))
            with _leaf_cache_lock:
                _leaf_cache[cache_key] = result
            return result

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)

    try:
        san = x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(hostname))])
    except ValueError:
        san = x509.SubjectAlternativeName([x509.DNSName(hostname)])

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=LEAF_VALIDITY_DAYS))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    key_path.write_bytes(
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))

    result = (str(key_path), str(cert_path))
    with _leaf_cache_lock:
        _leaf_cache[cache_key] = result
    return result
