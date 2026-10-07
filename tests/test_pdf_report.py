from app.services.pdf_report import (
    generate_pdf,
)


def test_pdf_generation():
    scan = {
        "target": "example.com",
        "scanned_at": (
            "2026-10-07T12:00:00+00:00"
        ),
        "assessment": {
            "score": 100,
            "grade": "A+",
            "findings": [
                {
                    "severity": "INFO",
                    "title": "Test finding",
                    "detail": "Test detail",
                }
            ],
            "recommendations": [
                "Continue monitoring."
            ],
        },
        "certificate": {
            "common_name": "example.com",
            "issuer_common_name": "Example CA",
            "issuer_organization": "Example",
            "not_before": (
                "2026-09-01T00:00:00+00:00"
            ),
            "not_after": (
                "2026-12-01T00:00:00+00:00"
            ),
            "days_remaining": 55,
            "sans": [
                "example.com",
                "*.example.com",
            ],
            "public_key": {
                "description":
                    "ECDSA secp256r1",
            },
            "signature_algorithm":
                "sha256",
            "serial_number": "1234",
            "sha256": "AA:BB",
            "sha1": "CC:DD",
        },
        "connection": {
            "tls_version": "TLSv1.3",
            "cipher":
                "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
        },
        "validation": {
            "trust_valid": True,
            "hostname_valid": True,
        },
        "tls_versions": [
            {
                "name": "TLS 1.2",
                "supported": True,
                "cipher":
                    "ECDHE-ECDSA-AES128-GCM-SHA256",
            },
            {
                "name": "TLS 1.3",
                "supported": True,
                "cipher":
                    "TLS_AES_256_GCM_SHA384",
            },
        ],
        "http": {
            "status_code": 200,
            "final_url":
                "https://example.com/",
            "server": "example",
            "hsts_enabled": True,
            "security_headers": {
                "strict-transport-security":
                    "max-age=31536000",
                "content-security-policy":
                    "default-src 'self'",
                "x-content-type-options":
                    "nosniff",
                "x-frame-options":
                    "DENY",
                "referrer-policy":
                    "strict-origin",
                "permissions-policy":
                    "camera=()",
            },
        },
        "story": {
            "headline":
                "Certificate posture appears stable.",
            "paragraphs": [
                "This is a test report."
            ],
        },
        "lifecycle": {
            "available": True,
            "issued_friendly":
                "Sep 01, 2026",
            "expires_friendly":
                "Dec 01, 2026",
            "progress": 40.0,
            "days_remaining": 55,
        },
        "comparison": {
            "summary":
                "No material changes detected.",
            "changes": [],
        },
        "pki": {
            "chain": {
                "available": False,
                "verified": False,
                "certificates": [],
                "error": "Not tested",
            },
            "ct": {
                "available": False,
                "records": [],
                "discovered_names": [],
                "error": "Not tested",
            },
        },
    }

    path = generate_pdf(
        scan,
        report_id="test_report",
    )

    assert path.exists()
    assert path.stat().st_size > 1000
