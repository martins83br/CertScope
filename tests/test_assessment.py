from app.core.assessment import assess_scan


def base_scan():
    return {
        "certificate": {
            "days_remaining": 90,
            "signature_algorithm": "sha256",
            "public_key": {
                "type": "EC",
                "size": 256,
            },
        },
        "connection": {
            "tls_version": "TLSv1.3",
        },
        "validation": {
            "trust_valid": True,
            "hostname_valid": True,
        },
        "tls_versions": [
            {"name": "TLS 1.0", "supported": False},
            {"name": "TLS 1.1", "supported": False},
            {"name": "TLS 1.2", "supported": True},
            {"name": "TLS 1.3", "supported": True},
        ],
        "http": {
            "available": True,
            "hsts_enabled": True,
            "security_headers": {
                "x-content-type-options": "nosniff",
                "content-security-policy": "default-src 'self'",
            },
        },
    }


def test_strong_assessment():
    assessment = assess_scan(base_scan())

    assert assessment["score"] == 100
    assert assessment["grade"] == "A+"


def test_expiration_penalty():
    scan = base_scan()
    scan["certificate"]["days_remaining"] = 20

    assessment = assess_scan(scan)

    assert assessment["score"] == 85
    assert assessment["grade"] == "B+"


def test_legacy_tls_penalty():
    scan = base_scan()
    scan["tls_versions"][0]["supported"] = True
    scan["tls_versions"][1]["supported"] = True

    assessment = assess_scan(scan)

    assert assessment["score"] == 75
    assert assessment["grade"] == "B-"


def test_hostname_failure():
    scan = base_scan()
    scan["validation"]["hostname_valid"] = False

    assessment = assess_scan(scan)

    assert assessment["score"] == 65
    assert assessment["grade"] == "C"
