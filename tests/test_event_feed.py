from app.core.event_feed import (
    build_event_feed,
    event_counts,
)


def test_event_feed():
    scans = [
        {
            "id": "scan1",
            "data": {
                "target":
                    "example.com",
                "scanned_at":
                    "2026-10-07T12:00:00+00:00",
                "risk_intelligence": {
                    "events": [
                        {
                            "type":
                                "TEST",
                            "severity":
                                "HIGH",
                            "title":
                                "Test event",
                            "detail":
                                "Test detail",
                        }
                    ]
                },
            },
        }
    ]

    feed = build_event_feed(
        scans
    )

    assert len(feed) == 1

    assert (
        feed[0]["target"]
        == "example.com"
    )

    counts = event_counts(
        feed
    )

    assert (
        counts["HIGH"]
        == 1
    )
