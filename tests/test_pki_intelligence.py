from app.core.pki_intelligence import (
    _extract_pem_certificates,
)


def test_empty_certificate_input():
    result = _extract_pem_certificates(
        "no certificates here"
    )

    assert result == []


def test_invalid_pem_is_ignored():
    text = """
-----BEGIN CERTIFICATE-----
INVALID
-----END CERTIFICATE-----
"""

    result = _extract_pem_certificates(
        text
    )

    assert result == []
