from app.core.compare import compare_snapshots


def _snapshot(
    fingerprint,
):
    return {
        "target": "example.com",

        "certificate": {
            "sha256_fingerprint":
                fingerprint,

            "serial_number":
                "123",

            "issuer_common_name":
                "Test CA",

            "not_after":
                "2027-01-01T00:00:00+00:00",

            "public_key": {
                "description":
                    "ECDSA secp256r1"
            },

            "signature_algorithm":
                "sha256",

            "sans": [
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
            "score": 100,
            "grade": "A+",
        },
    }


def test_compare_uses_current_fingerprint():
    before = _snapshot(
        "AA:AA"
    )

    after = _snapshot(
        "BB:BB"
    )

    result = compare_snapshots(
        before,
        after,
    )

    fingerprint_rows = [
        row
        for row in result[
            "changed_rows"
        ]
        if row["field"]
        == "SHA-256 Fingerprint"
    ]

    assert len(
        fingerprint_rows
    ) == 1

    assert (
        fingerprint_rows[0]["before"]
        == "AA:AA"
    )

    assert (
        fingerprint_rows[0]["after"]
        == "BB:BB"
    )
