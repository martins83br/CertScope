import json

import app.services.watchlist as watchlist


def test_atomic_watchlist_write(
    tmp_path,
    monkeypatch,
):
    directory = (
        tmp_path
        / "watchlist"
    )

    file_path = (
        directory
        / "targets.json"
    )

    monkeypatch.setattr(
        watchlist,
        "WATCHLIST_DIR",
        directory,
    )

    monkeypatch.setattr(
        watchlist,
        "WATCHLIST_FILE",
        file_path,
    )

    payload = [
        {
            "target":
                "example.com",

            "added_at":
                "2026-10-07T00:00:00+00:00",
        }
    ]

    watchlist.save_watchlist(
        payload
    )

    assert file_path.exists()

    assert json.loads(
        file_path.read_text(
            encoding="utf-8"
        )
    ) == payload

    leftovers = list(
        directory.glob(
            ".targets-*.tmp"
        )
    )

    assert leftovers == []
