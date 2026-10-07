from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from app.core.scanner import normalize_target


BASE_DIR = Path(__file__).resolve().parents[2]

WATCHLIST_DIR = (
    BASE_DIR
    / "data"
    / "watchlist"
)

WATCHLIST_FILE = (
    WATCHLIST_DIR
    / "targets.json"
)


def _ensure_storage() -> None:
    WATCHLIST_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    if not WATCHLIST_FILE.exists():
        save_watchlist([])


def load_watchlist() -> list[dict]:
    _ensure_storage()

    try:
        data = json.loads(
            WATCHLIST_FILE.read_text(
                encoding="utf-8"
            )
        )

        if not isinstance(data, list):
            return []

        return data

    except (
        OSError,
        json.JSONDecodeError,
    ):
        return []


def save_watchlist(
    targets: list[dict],
) -> None:
    WATCHLIST_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload = (
        json.dumps(
            targets,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )

    descriptor = None
    temporary_path = None

    try:
        descriptor, temporary_name = (
            tempfile.mkstemp(
                prefix=".targets-",
                suffix=".tmp",
                dir=WATCHLIST_DIR,
                text=True,
            )
        )

        temporary_path = Path(
            temporary_name
        )

        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
        ) as handle:
            descriptor = None

            handle.write(payload)
            handle.flush()
            os.fsync(
                handle.fileno()
            )

        os.replace(
            temporary_path,
            WATCHLIST_FILE,
        )

    finally:
        if descriptor is not None:
            os.close(descriptor)

        if (
            temporary_path
            and temporary_path.exists()
        ):
            temporary_path.unlink(
                missing_ok=True
            )


def add_target(
    target: str,
) -> dict:
    hostname = normalize_target(
        target
    )

    targets = load_watchlist()

    for item in targets:
        if (
            item.get("target")
            == hostname
        ):
            return item

    item = {
        "target": hostname,
        "added_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    targets.append(item)

    targets.sort(
        key=lambda entry: (
            entry.get(
                "target",
                "",
            )
        )
    )

    save_watchlist(targets)

    return item


def remove_target(
    target: str,
) -> None:
    hostname = normalize_target(
        target
    )

    targets = [
        item
        for item
        in load_watchlist()
        if (
            item.get("target")
            != hostname
        )
    ]

    save_watchlist(targets)
