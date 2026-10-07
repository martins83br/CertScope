from app.core.intelligence import (
    build_certificate_story,
    compare_scans,
)


def sample_scan(
    fingerprint="AA:BB",
    issuer="WE1",
    score=95,
):
    return {
        "target": "example.com",
        "scanned_at": "2026-10-07T12:00:00+00:00",
        "certificate": {
            "sha256": fingerprint,
            "issuer_common_name": issuer,
            "issuer_organization": "Example CA",
            "serial_number": "1234",
            "not_after": "2026-12-01T00:00:00+00:00",
            "days_remaining": 55,
            "sans": [
                "example.com",
                "*.example.com",
            ],
            "public_key": {
                "description": "ECDSA secp256r1",
            },
        },
        "connection": {
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
        },
        "validation": {
            "trust_valid": True,
            "hostname_valid": True,
        },
        "assessment": {
            "score": score,
            "grade": "A",
            "findings": [],
            "recommendations": [],
        },
    }


def test_first_scan_is_baseline():
    current = sample_scan()

    comparison = compare_scans(None, current)

    assert comparison["available"] is False
    assert comparison["changed"] is False


def test_same_scan_is_stable():
    previous = sample_scan()
    current = sample_scan()

    comparison = compare_scans(previous, current)

    assert comparison["available"] is True
    assert comparison["changed"] is False


def test_certificate_change_detected():
    previous = sample_scan(
        fingerprint="AA:BB",
    )

    current = sample_scan(
        fingerprint="CC:DD",
    )

    comparison = compare_scans(
        previous,
        current,
    )

    assert comparison["changed"] is True

    fields = [
        change["field"]
        for change in comparison["changes"]
    ]

    assert "Certificate fingerprint" in fields


def test_story_reports_rotation():
    previous = sample_scan(
        fingerprint="AA:BB",
    )

    current = sample_scan(
        fingerprint="CC:DD",
    )

    comparison = compare_scans(
        previous,
        current,
    )

    story = build_certificate_story(
        previous,
        current,
        comparison,
    )

    assert story["level"] == "CHANGE"
    assert "rotation" in story["headline"].lower()
