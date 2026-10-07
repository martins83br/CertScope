from __future__ import annotations

from app.core.risk_intelligence import (
    SEVERITY_ORDER,
)


def build_event_feed(
    scans: list[dict],
    limit: int = 20,
) -> list[dict]:
    feed = []

    for record in scans:
        data = record.get(
            "data",
            {},
        )

        risk = data.get(
            "risk_intelligence",
            {},
        )

        for event in risk.get(
            "events",
            [],
        ):
            feed.append({
                "scan_id": record.get(
                    "id"
                ),
                "target": data.get(
                    "target"
                ),
                "scanned_at": data.get(
                    "scanned_at"
                ),
                "type": event.get(
                    "type"
                ),
                "severity": event.get(
                    "severity",
                    "INFO",
                ),
                "title": event.get(
                    "title"
                ),
                "detail": event.get(
                    "detail"
                ),
                "before": event.get(
                    "before"
                ),
                "after": event.get(
                    "after"
                ),
            })

    feed.sort(
        key=lambda item: (
            item.get(
                "scanned_at"
            )
            or ""
        ),
        reverse=True,
    )

    return feed[:limit]


def event_counts(
    feed: list[dict],
) -> dict:
    counts = {
        "INFO": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for item in feed:
        severity = item.get(
            "severity",
            "INFO",
        )

        if severity in counts:
            counts[
                severity
            ] += 1

    return counts
