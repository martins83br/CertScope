from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone


def _parse_date(value: str | None):
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except (ValueError, TypeError):
        return None


def friendly_date(value: str | None) -> str:
    dt = _parse_date(value)

    if not dt:
        return value or "Unknown"

    return dt.strftime("%b %d, %Y")


def build_lifecycle(scan: dict) -> dict:
    cert = scan.get("certificate", {})

    issued = _parse_date(cert.get("not_before"))
    expires = _parse_date(cert.get("not_after"))
    now = datetime.now(timezone.utc)

    if not issued or not expires:
        return {
            "available": False,
        }

    total = max(
        1,
        (expires - issued).total_seconds(),
    )

    elapsed = (
        now - issued
    ).total_seconds()

    progress = max(
        0,
        min(
            100,
            (elapsed / total) * 100,
        ),
    )

    return {
        "available": True,
        "issued": issued.isoformat(),
        "expires": expires.isoformat(),
        "issued_friendly": friendly_date(
            cert.get("not_before")
        ),
        "expires_friendly": friendly_date(
            cert.get("not_after")
        ),
        "days_remaining": cert.get(
            "days_remaining",
            0,
        ),
        "progress": round(progress, 1),
    }


def _short_issuer(value: str) -> str:
    if not value:
        return "Unknown"

    parts = [
        part.strip()
        for part in value.split(",")
    ]

    for part in reversed(parts):
        if part.startswith("CN="):
            return part[3:].strip()

    return value


def build_ca_timeline(ct: dict) -> list[dict]:
    if not ct or not ct.get("available"):
        return []

    grouped = defaultdict(
        lambda: {
            "count": 0,
            "first_seen": None,
            "last_seen": None,
            "issuer_name": "",
        }
    )

    for record in ct.get("records", []):
        issuer = record.get(
            "issuer_name",
            "Unknown",
        )

        short = _short_issuer(issuer)

        date_value = (
            record.get("not_before")
            or record.get("entry_timestamp")
        )

        date = _parse_date(date_value)

        item = grouped[short]

        item["issuer_name"] = issuer
        item["count"] += 1

        if date:
            if (
                item["first_seen"] is None
                or date < item["first_seen"]
            ):
                item["first_seen"] = date

            if (
                item["last_seen"] is None
                or date > item["last_seen"]
            ):
                item["last_seen"] = date

    result = []

    for short_name, item in grouped.items():
        result.append({
            "name": short_name,
            "issuer_name": item[
                "issuer_name"
            ],
            "count": item["count"],
            "first_seen": (
                item["first_seen"].isoformat()
                if item["first_seen"]
                else None
            ),
            "last_seen": (
                item["last_seen"].isoformat()
                if item["last_seen"]
                else None
            ),
            "first_seen_friendly": (
                item["first_seen"].strftime(
                    "%b %Y"
                )
                if item["first_seen"]
                else "Unknown"
            ),
            "last_seen_friendly": (
                item["last_seen"].strftime(
                    "%b %Y"
                )
                if item["last_seen"]
                else "Unknown"
            ),
        })

    result.sort(
        key=lambda item: (
            item["last_seen"] or ""
        ),
        reverse=True,
    )

    return result


def build_local_timeline(
    scans: list[dict],
) -> list[dict]:
    timeline = []

    for item in scans:
        data = item.get("data", item)

        assessment = data.get(
            "assessment",
            {},
        )

        certificate = data.get(
            "certificate",
            {},
        )

        timeline.append({
            "id": item.get("id"),
            "target": data.get(
                "target",
                "Unknown",
            ),
            "scanned_at": data.get(
                "scanned_at",
            ),
            "scanned_friendly": (
                friendly_date(
                    data.get("scanned_at")
                )
            ),
            "score": assessment.get(
                "score",
            ),
            "grade": assessment.get(
                "grade",
            ),
            "fingerprint": (
                certificate.get("sha256")
            ),
            "issuer": (
                certificate.get(
                    "issuer_common_name"
                )
            ),
            "expires": (
                certificate.get(
                    "not_after"
                )
            ),
            "days_remaining": (
                certificate.get(
                    "days_remaining"
                )
            ),
        })

    return timeline
