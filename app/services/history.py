from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
SCAN_DIR = BASE_DIR / "data" / "scans"


def _safe_hostname(hostname: str) -> str:
    return hostname.replace("/", "_").replace("\\", "_")


def save_scan(result: dict) -> Path:
    SCAN_DIR.mkdir(parents=True, exist_ok=True)

    hostname = _safe_hostname(result["target"])
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

    path = SCAN_DIR / f"{hostname}_{timestamp}.json"

    with path.open("w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=False)

    return path


def list_scans(hostname: str | None = None) -> list[dict]:
    SCAN_DIR.mkdir(parents=True, exist_ok=True)

    records = []

    for path in SCAN_DIR.glob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)

            if hostname and data.get("target") != hostname:
                continue

            records.append({
                "id": path.stem,
                "path": path,
                "data": data,
            })

        except (OSError, json.JSONDecodeError):
            continue

    records.sort(
        key=lambda item: item["data"].get("scanned_at", ""),
        reverse=True,
    )

    return records


def get_previous_scan(hostname: str) -> dict | None:
    scans = list_scans(hostname)

    if not scans:
        return None

    return scans[0]["data"]


def load_scan(scan_id: str) -> dict | None:
    safe_id = Path(scan_id).name
    path = SCAN_DIR / f"{safe_id}.json"

    if not path.exists():
        return None

    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
