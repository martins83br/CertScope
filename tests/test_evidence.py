from app.services.evidence import (
    build_evidence_package,
    snapshot_hash,
)


def sample_scan():
    return {
        "target": "example.com",
        "scanned_at": (
            "2026-10-07T12:00:00+00:00"
        ),
        "certificate": {
            "sha256": "AA:BB:CC",
        },
        "assessment": {
            "score": 95,
            "grade": "A",
        },
    }


def test_hash_is_deterministic():
    data = sample_scan()

    first = snapshot_hash(
        data
    )

    second = snapshot_hash(
        data
    )

    assert first == second
    assert len(first) == 64


def test_hash_changes_with_data():
    first = sample_scan()
    second = sample_scan()

    second[
        "assessment"
    ][
        "score"
    ] = 80

    assert (
        snapshot_hash(first)
        != snapshot_hash(second)
    )


def test_evidence_package():
    data = sample_scan()

    package = build_evidence_package(
        data,
        "example_scan",
    )

    assert package[
        "scan_id"
    ] == "example_scan"

    assert package[
        "target"
    ] == "example.com"

    assert package[
        "integrity"
    ][
        "algorithm"
    ] == "SHA-256"

    assert package[
        "scan"
    ] == data
