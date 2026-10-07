from app.core.risk_intelligence import (
    build_risk_intelligence,
    expiration_band,
)


def scan(
    fingerprint="AA",
    issuer="Example CA",
    days=90,
    score=95,
    sans=None,
    tls="TLSv1.3",
):
    return {
        "certificate": {
            "sha256": fingerprint,
            "issuer_common_name":
                issuer,
            "days_remaining":
                days,
            "sans": (
                sans
                or [
                    "example.com"
                ]
            ),
            "public_key": {
                "description":
                    "ECDSA secp256r1",
            },
        },
        "connection": {
            "tls_version":
                tls,
            "cipher":
                "TLS_AES_256_GCM_SHA384",
        },
        "validation": {
            "trust_valid": True,
            "hostname_valid": True,
        },
        "assessment": {
            "score": score,
        },
    }


def event_types(result):
    return {
        item["type"]
        for item in result[
            "events"
        ]
    }


def test_expiration_bands():
    assert (
        expiration_band(90)
        == "HEALTHY"
    )

    assert (
        expiration_band(60)
        == "60_DAYS"
    )

    assert (
        expiration_band(30)
        == "30_DAYS"
    )

    assert (
        expiration_band(14)
        == "14_DAYS"
    )

    assert (
        expiration_band(7)
        == "7_DAYS"
    )

    assert (
        expiration_band(1)
        == "1_DAY"
    )


def test_baseline_event():
    result = build_risk_intelligence(
        None,
        scan(),
    )

    assert (
        "BASELINE_CREATED"
        in event_types(result)
    )


def test_rotation_event():
    result = build_risk_intelligence(
        scan(
            fingerprint="AA"
        ),
        scan(
            fingerprint="BB"
        ),
    )

    assert (
        "CERTIFICATE_ROTATED"
        in event_types(result)
    )


def test_issuer_event():
    result = build_risk_intelligence(
        scan(
            issuer="CA One"
        ),
        scan(
            issuer="CA Two"
        ),
    )

    assert (
        "ISSUER_CHANGED"
        in event_types(result)
    )


def test_san_added_removed():
    result = build_risk_intelligence(
        scan(
            sans=[
                "example.com",
                "old.example.com",
            ]
        ),
        scan(
            sans=[
                "example.com",
                "new.example.com",
            ]
        ),
    )

    types = event_types(
        result
    )

    assert "SAN_ADDED" in types
    assert "SAN_REMOVED" in types


def test_score_drop():
    result = build_risk_intelligence(
        scan(
            score=95
        ),
        scan(
            score=70
        ),
    )

    events = [
        event
        for event in result[
            "events"
        ]
        if event["type"]
        == "SCORE_CHANGED"
    ]

    assert len(events) == 1

    assert (
        events[0]["severity"]
        == "HIGH"
    )


def test_expiration_threshold():
    result = build_risk_intelligence(
        scan(
            days=65
        ),
        scan(
            days=59
        ),
    )

    assert (
        "EXPIRATION_THRESHOLD"
        in event_types(result)
    )


def test_empty_v08_snapshot_still_creates_baseline():
    previous = scan()

    previous["risk_intelligence"] = {
        "events": [],
        "summary": {
            "count": 0,
        },
    }

    current = scan()

    result = build_risk_intelligence(
        previous,
        current,
    )

    assert (
        "RISK_BASELINE_CREATED"
        in event_types(result)
    )


def test_recorded_risk_baseline_does_not_repeat():
    previous = scan()

    previous["risk_intelligence"] = {
        "events": [
            {
                "type":
                    "RISK_BASELINE_CREATED",
                "severity":
                    "INFO",
            }
        ],
        "summary": {
            "count": 1,
        },
    }

    current = scan()

    result = build_risk_intelligence(
        previous,
        current,
    )

    assert (
        "RISK_BASELINE_CREATED"
        not in event_types(result)
    )
