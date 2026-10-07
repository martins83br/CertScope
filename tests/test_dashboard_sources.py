from app.core.dashboard import (
    build_dashboard,
)


def scan_record(
    target,
    scan_id,
):
    return {
        "id": scan_id,
        "data": {
            "target": target,
            "scanned_at":
                "2026-10-07T12:00:00+00:00",

            "validation": {
                "trust_valid": True,
                "hostname_valid": True,
            },

            "certificate": {
                "days_remaining": 90,
                "issuer_common_name":
                    "Test CA",
                "sha256_fingerprint":
                    "AA",
            },

            "assessment": {
                "score": 100,
                "grade": "A+",
            },
        },
    }


def test_dashboard_distinguishes_sources():
    dashboard = build_dashboard(
        [
            {
                "target":
                    "watched.example"
            }
        ],
        [
            scan_record(
                "watched.example",
                "watched-scan",
            ),

            scan_record(
                "historical.example",
                "historical-scan",
            ),
        ],
    )

    by_target = {
        asset["target"]: asset
        for asset
        in dashboard["assets"]
    }

    assert (
        by_target[
            "watched.example"
        ]["watched"]
        is True
    )

    assert (
        by_target[
            "watched.example"
        ]["source"]
        == "WATCHLIST"
    )

    assert (
        by_target[
            "historical.example"
        ]["watched"]
        is False
    )

    assert (
        by_target[
            "historical.example"
        ]["source"]
        == "HISTORICAL"
    )

    assert (
        dashboard["watched_count"]
        == 1
    )

    assert (
        dashboard[
            "historical_count"
        ]
        == 1
    )
