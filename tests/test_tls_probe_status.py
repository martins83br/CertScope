from app.core.assessment import assess_scan


def base_scan():
    return {
        "validation": {
            "trust_valid": True,
            "hostname_valid": True,
        },
        "certificate": {
            "days_remaining": 100,
            "expired": False,
            "not_yet_valid": False,
            "public_key": {
                "type": "RSA",
                "size": 2048,
            },
            "signature_algorithm": "sha256",
        },
        "http": {
            "available": False,
        },
        "tls_versions": [],
    }


def test_inconclusive_tls_does_not_reduce_score():
    scan = base_scan()

    scan["tls_versions"] = [
        {
            "name": "TLS 1.2",
            "supported": False,
            "status": "INCONCLUSIVE",
        },
        {
            "name": "TLS 1.3",
            "supported": False,
            "status": "LOCAL_UNSUPPORTED",
        },
    ]

    result = assess_scan(scan)

    assert result["score"] == 100


def test_rejected_tls12_reduces_score():
    scan = base_scan()

    scan["tls_versions"] = [
        {
            "name": "TLS 1.2",
            "supported": False,
            "status": "REJECTED",
        }
    ]

    result = assess_scan(scan)

    assert result["score"] == 85


def test_supported_tls10_reduces_score():
    scan = base_scan()

    scan["tls_versions"] = [
        {
            "name": "TLS 1.0",
            "supported": True,
            "status": "SUPPORTED",
        }
    ]

    result = assess_scan(scan)

    assert result["score"] == 85
