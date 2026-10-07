from app.core.dashboard import (
    build_asset,
    build_dashboard,
    certificate_rotated,
    operational_status,
)


def sample_scan(
    target="example.com",
    score=95,
    days=90,
    fingerprint="AA",
):
    return {
        "target": target,
        "scanned_at": (
            "2026-10-07T12:00:00+00:00"
        ),
        "validation": {
            "trust_valid": True,
            "hostname_valid": True,
        },
        "certificate": {
            "days_remaining": days,
            "sha256": fingerprint,
            "issuer_common_name": "Example CA",
        },
        "assessment": {
            "score": score,
            "grade": "A",
        },
    }


def test_healthy_status():
    result = operational_status(
        sample_scan()
    )

    assert result["name"] == "HEALTHY"


def test_expiration_attention():
    result = operational_status(
        sample_scan(
            days=20
        )
    )

    assert result["name"] == "ATTENTION"


def test_expiration_critical():
    result = operational_status(
        sample_scan(
            days=5
        )
    )

    assert result["name"] == "CRITICAL"


def test_validation_critical():
    scan = sample_scan()

    scan[
        "validation"
    ][
        "trust_valid"
    ] = False

    result = operational_status(
        scan
    )

    assert result["name"] == "CRITICAL"


def test_rotation_detection():
    before = sample_scan(
        fingerprint="AA"
    )

    after = sample_scan(
        fingerprint="BB"
    )

    assert certificate_rotated(
        before,
        after,
    ) is True


def test_dashboard_counts():
    scans = [
        {
            "id": "scan1",
            "data": sample_scan(
                target="one.example",
                days=90,
            ),
        },
        {
            "id": "scan2",
            "data": sample_scan(
                target="two.example",
                days=5,
            ),
        },
    ]

    watchlist = [
        {
            "target": "one.example"
        },
        {
            "target": "two.example"
        },
        {
            "target": "three.example"
        },
    ]

    result = build_dashboard(
        watchlist,
        scans,
    )

    assert result[
        "counts"
    ][
        "TOTAL"
    ] == 3

    assert result[
        "counts"
    ][
        "HEALTHY"
    ] == 1

    assert result[
        "counts"
    ][
        "CRITICAL"
    ] == 1

    assert result[
        "counts"
    ][
        "UNSCANNED"
    ] == 1
