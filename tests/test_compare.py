from app.core.compare import (
    compare_snapshots,
)


def scan(
    fingerprint="AA",
    score=90,
    sans=None,
):
    return {
        "target": "example.com",
        "scanned_at": (
            "2026-10-07T10:00:00+00:00"
        ),
        "certificate": {
            "sha256": fingerprint,
            "serial_number": "123",
            "issuer_common_name": "CA",
            "not_after": (
                "2026-12-01T00:00:00+00:00"
            ),
            "public_key": {
                "description":
                    "ECDSA secp256r1",
            },
            "signature_algorithm":
                "sha256",
            "sans": sans or [
                "example.com"
            ],
        },
        "connection": {
            "tls_version":
                "TLSv1.3",
            "cipher":
                "TLS_AES_256_GCM_SHA384",
        },
        "validation": {
            "trust_valid": True,
            "hostname_valid": True,
        },
        "http": {
            "hsts_enabled": True,
            "security_headers": {},
        },
        "assessment": {
            "score": score,
            "grade": "A",
        },
    }


def test_identical_snapshots():
    result = compare_snapshots(
        scan(),
        scan(),
    )

    assert result[
        "changed_count"
    ] == 0

    assert result[
        "score_delta"
    ] == 0


def test_certificate_change():
    result = compare_snapshots(
        scan(
            fingerprint="AA"
        ),
        scan(
            fingerprint="BB"
        ),
    )

    assert result[
        "changed_count"
    ] >= 1


def test_san_added():
    result = compare_snapshots(
        scan(
            sans=[
                "example.com"
            ]
        ),
        scan(
            sans=[
                "example.com",
                "api.example.com",
            ]
        ),
    )

    assert (
        "api.example.com"
        in result["added_sans"]
    )


def test_score_evolution():
    result = compare_snapshots(
        scan(score=80),
        scan(score=95),
    )

    assert result[
        "score_delta"
    ] == 15
