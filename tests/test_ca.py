import datetime

from cryptography import x509

import ca


def test_ensure_root_ca_generates_self_signed_ca(tmp_path):
    ca_key, ca_cert, key_path, cert_path = ca.ensure_root_ca(ca_dir=tmp_path / "ca")

    assert key_path.exists()
    assert cert_path.exists()
    assert ca_cert.issuer == ca_cert.subject

    basic_constraints = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic_constraints.ca is True

    # a self-signed cert must verify against its own public key
    ca_cert.verify_directly_issued_by(ca_cert)


def test_ensure_root_ca_reuses_existing_ca_on_second_call(tmp_path):
    ca_dir = tmp_path / "ca"
    _, first_cert, _, _ = ca.ensure_root_ca(ca_dir=ca_dir)
    _, second_cert, _, _ = ca.ensure_root_ca(ca_dir=ca_dir)

    assert first_cert.serial_number == second_cert.serial_number


def test_get_leaf_cert_is_signed_by_root_and_matches_hostname(tmp_path):
    ca_key, ca_cert, _, _ = ca.ensure_root_ca(ca_dir=tmp_path / "ca")

    key_path, cert_path = ca.get_leaf_cert(
        "example.com", ca_key, ca_cert, cache_dir=tmp_path / "leaves"
    )
    leaf_cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())

    leaf_cert.verify_directly_issued_by(ca_cert)

    san = leaf_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["example.com"]

    now = datetime.datetime.now(datetime.timezone.utc)
    assert leaf_cert.not_valid_after_utc > now


def test_get_leaf_cert_is_cached_between_calls(tmp_path):
    ca_key, ca_cert, _, _ = ca.ensure_root_ca(ca_dir=tmp_path / "ca")
    cache_dir = tmp_path / "leaves"

    first_key_path, first_cert_path = ca.get_leaf_cert(
        "example.com", ca_key, ca_cert, cache_dir=cache_dir
    )
    second_key_path, second_cert_path = ca.get_leaf_cert(
        "example.com", ca_key, ca_cert, cache_dir=cache_dir
    )

    assert first_key_path == second_key_path
    assert first_cert_path == second_cert_path

    first_cert = x509.load_pem_x509_certificate(open(first_cert_path, "rb").read())
    second_cert = x509.load_pem_x509_certificate(open(second_cert_path, "rb").read())
    assert first_cert.serial_number == second_cert.serial_number
