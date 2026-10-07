from app.core.timeline import (
    build_ca_timeline,
    build_lifecycle,
)


def test_lifecycle_available():
    scan = {
        "certificate": {
            "not_before":
                "2026-09-01T00:00:00+00:00",
            "not_after":
                "2026-12-01T00:00:00+00:00",
            "days_remaining": 55,
        }
    }

    result = build_lifecycle(
        scan
    )

    assert result[
        "available"
    ] is True


def test_ca_timeline():
    ct = {
        "available": True,
        "records": [
            {
                "issuer_name":
                    "C=US, CN=Example CA",
                "not_before":
                    "2026-01-01T00:00:00",
            },
            {
                "issuer_name":
                    "C=US, CN=Example CA",
                "not_before":
                    "2026-06-01T00:00:00",
            },
        ],
    }

    result = build_ca_timeline(
        ct
    )

    assert len(result) == 1

    assert result[0][
        "count"
    ] == 2
