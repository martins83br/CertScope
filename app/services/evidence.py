from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
EVIDENCE_DIR = BASE_DIR / "data" / "evidence"


def canonical_json(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def snapshot_hash(data: dict) -> str:
    return hashlib.sha256(
        canonical_json(data)
    ).hexdigest().upper()


def build_evidence_package(
    scan: dict,
    scan_id: str,
) -> dict:
    captured_hash = snapshot_hash(scan)

    return {
        "format": "CertScope Evidence Package",
        "format_version": "1.0",
        "scan_id": scan_id,
        "target": scan.get("target"),
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "integrity": {
            "algorithm": "SHA-256",
            "snapshot_hash": captured_hash,
            "scope": (
                "Canonical JSON representation "
                "of the embedded scan object"
            ),
        },
        "scan": scan,
    }


def write_evidence_package(
    scan: dict,
    scan_id: str,
) -> Path:
    EVIDENCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    package = build_evidence_package(
        scan,
        scan_id,
    )

    path = (
        EVIDENCE_DIR
        / f"CertScope_Evidence_{scan_id}.json"
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            package,
            handle,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

    return path
