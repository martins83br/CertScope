from __future__ import annotations

from datetime import datetime
from typing import Any


def _parse_datetime(
    value: str | None,
):
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            value.replace(
                "Z",
                "+00:00",
            )
        )
    except (
        ValueError,
        TypeError,
    ):
        return None


def operational_status(
    scan: dict | None,
) -> dict:
    if not scan:
        return {
            "name": "UNSCANNED",
            "label": "Unscanned",
            "reason": (
                "No local snapshot "
                "has been recorded yet."
            ),
        }

    validation = scan.get(
        "validation",
        {},
    )

    certificate = scan.get(
        "certificate",
        {},
    )

    assessment = scan.get(
        "assessment",
        {},
    )

    trust = validation.get(
        "trust_valid"
    )

    hostname = validation.get(
        "hostname_valid"
    )

    days = certificate.get(
        "days_remaining"
    )

    score = assessment.get(
        "score"
    )

    if (
        trust is False
        or hostname is False
    ):
        return {
            "name": "CRITICAL",
            "label": "Critical",
            "reason": (
                "Certificate trust or "
                "hostname validation failed."
            ),
        }

    if isinstance(days, int):
        if days <= 7:
            return {
                "name": "CRITICAL",
                "label": "Critical",
                "reason": (
                    f"Certificate expires "
                    f"in {days} day(s)."
                ),
            }

        if days <= 30:
            return {
                "name": "ATTENTION",
                "label": "Attention",
                "reason": (
                    f"Certificate expires "
                    f"in {days} day(s)."
                ),
            }

        if days <= 60:
            return {
                "name": "ATTENTION",
                "label": "Attention",
                "reason": (
                    "Certificate renewal "
                    "window is approaching."
                ),
            }

    if (
        isinstance(score, int)
        and score < 78
    ):
        return {
            "name": "ATTENTION",
            "label": "Attention",
            "reason": (
                "Security score is below "
                "the healthy threshold."
            ),
        }

    return {
        "name": "HEALTHY",
        "label": "Healthy",
        "reason": (
            "No immediate operational "
            "certificate issue detected."
        ),
    }


def certificate_rotated(
    previous: dict | None,
    current: dict | None,
) -> bool:
    if not previous or not current:
        return False

    before = (
        previous
        .get("certificate", {})
        .get("sha256")
    )

    after = (
        current
        .get("certificate", {})
        .get("sha256")
    )

    return bool(
        before
        and after
        and before != after
    )


def latest_change_summary(
    previous: dict | None,
    current: dict | None,
) -> str:
    if not current:
        return "No scan recorded"

    if not previous:
        return "Baseline created"

    if certificate_rotated(
        previous,
        current,
    ):
        return "Certificate rotated"

    before_score = (
        previous
        .get("assessment", {})
        .get("score")
    )

    after_score = (
        current
        .get("assessment", {})
        .get("score")
    )

    if (
        before_score is not None
        and after_score is not None
        and before_score != after_score
    ):
        delta = after_score - before_score

        sign = (
            "+"
            if delta > 0
            else ""
        )

        return (
            f"Score changed "
            f"{sign}{delta}"
        )

    return "Stable"


def build_asset(
    target: str,
    scans: list[dict],
) -> dict:
    matching = [
        item
        for item in scans
        if (
            item.get(
                "data",
                {},
            ).get("target")
            == target
        )
    ]

    current_record = (
        matching[0]
        if matching
        else None
    )

    previous_record = (
        matching[1]
        if len(matching) > 1
        else None
    )

    current = (
        current_record.get("data")
        if current_record
        else None
    )

    previous = (
        previous_record.get("data")
        if previous_record
        else None
    )

    status = operational_status(
        current
    )

    certificate = (
        current.get(
            "certificate",
            {},
        )
        if current
        else {}
    )

    assessment = (
        current.get(
            "assessment",
            {},
        )
        if current
        else {}
    )

    scanned_at = (
        current.get(
            "scanned_at"
        )
        if current
        else None
    )

    risk_intelligence = (
        current.get(
            "risk_intelligence",
            {},
        )
        if current
        else {}
    )

    risk_summary = (
        risk_intelligence.get(
            "summary",
            {},
        )
    )

    risk_events = (
        risk_intelligence.get(
            "events",
            [],
        )
    )

    return {
        "target": target,
        "status": status,
        "risk_summary": risk_summary,
        "risk_events": risk_events,
        "score": assessment.get(
            "score"
        ),
        "grade": assessment.get(
            "grade"
        ),
        "days_remaining": (
            certificate.get(
                "days_remaining"
            )
        ),
        "issuer": certificate.get(
            "issuer_common_name"
        ),
        "scanned_at": scanned_at,
        "scan_id": (
            current_record.get("id")
            if current_record
            else None
        ),
        "previous_scan_id": (
            previous_record.get("id")
            if previous_record
            else None
        ),
        "rotation_detected": (
            certificate_rotated(
                previous,
                current,
            )
        ),
        "change_summary": (
            latest_change_summary(
                previous,
                current,
            )
        ),
    }


def build_dashboard(
    watchlist: list[dict],
    scans: list[dict],
) -> dict:
    watched_targets = {
        item.get("target")
        for item in watchlist
        if item.get("target")
    }

    historical_targets = {
        item.get(
            "data",
            {},
        ).get("target")
        for item in scans
        if item.get(
            "data",
            {},
        ).get("target")
    }

    targets = sorted(
        watched_targets
        | historical_targets
    )

    assets = []

    for target in targets:
        asset = build_asset(
            target,
            scans,
        )

        asset["watched"] = (
            target in watched_targets
        )

        asset["source"] = (
            "WATCHLIST"
            if asset["watched"]
            else "HISTORICAL"
        )

        assets.append(asset)

    counts = {
        "TOTAL": len(assets),
        "HEALTHY": 0,
        "ATTENTION": 0,
        "CRITICAL": 0,
        "UNSCANNED": 0,
    }

    for asset in assets:
        name = asset[
            "status"
        ][
            "name"
        ]

        if name in counts:
            counts[name] += 1

    watched_assets = [
        asset
        for asset in assets
        if asset["watched"]
    ]

    historical_assets = [
        asset
        for asset in assets
        if not asset["watched"]
    ]

    return {
        "assets": assets,
        "watched_assets": watched_assets,
        "historical_assets": historical_assets,
        "counts": counts,
        "watched_count": len(
            watched_assets
        ),
        "historical_count": len(
            historical_assets
        ),
    }
