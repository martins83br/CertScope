from pathlib import Path

import app.services.watchlist as watchlist


def test_watchlist_add_remove(
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

    item = watchlist.add_target(
        "Example.COM"
    )

    assert (
        item["target"]
        == "example.com"
    )

    items = (
        watchlist.load_watchlist()
    )

    assert len(items) == 1

    watchlist.remove_target(
        "example.com"
    )

    assert (
        watchlist.load_watchlist()
        == []
    )
