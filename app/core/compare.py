from __future__ import annotations


def _value(data: dict, *keys):
    current = data

    for key in keys:
        if not isinstance(
            current,
            dict,
        ):
            return None

        current = current.get(key)

    return current


def compare_snapshots(
    before: dict,
    after: dict,
) -> dict:
    fields = [
        (
            "Certificate",
            "SHA-256 Fingerprint",
            (
                "certificate",
                "sha256_fingerprint",
            ),
        ),
        (
            "Certificate",
            "Serial Number",
            (
                "certificate",
                "serial_number",
            ),
        ),
        (
            "Certificate",
            "Issuer",
            (
                "certificate",
                "issuer_common_name",
            ),
        ),
        (
            "Certificate",
            "Valid Until",
            (
                "certificate",
                "not_after",
            ),
        ),
        (
            "Cryptography",
            "Public Key",
            (
                "certificate",
                "public_key",
                "description",
            ),
        ),
        (
            "Cryptography",
            "Signature",
            (
                "certificate",
                "signature_algorithm",
            ),
        ),
        (
            "TLS",
            "Negotiated TLS",
            (
                "connection",
                "tls_version",
            ),
        ),
        (
            "TLS",
            "Cipher",
            (
                "connection",
                "cipher",
            ),
        ),
        (
            "Validation",
            "Trust",
            (
                "validation",
                "trust_valid",
            ),
        ),
        (
            "Validation",
            "Hostname",
            (
                "validation",
                "hostname_valid",
            ),
        ),
        (
            "HTTPS",
            "HSTS",
            (
                "http",
                "hsts_enabled",
            ),
        ),
        (
            "Assessment",
            "Score",
            (
                "assessment",
                "score",
            ),
        ),
        (
            "Assessment",
            "Grade",
            (
                "assessment",
                "grade",
            ),
        ),
    ]

    rows = []

    for category, label, keys in fields:
        before_value = _value(
            before,
            *keys,
        )

        after_value = _value(
            after,
            *keys,
        )

        # Backward compatibility for historical
        # CertScope snapshots that stored the
        # certificate fingerprint as "sha256".
        if label == "SHA-256 Fingerprint":
            if before_value is None:
                before_value = _value(
                    before,
                    "certificate",
                    "sha256",
                )

            if after_value is None:
                after_value = _value(
                    after,
                    "certificate",
                    "sha256",
                )

        rows.append({
            "category": category,
            "field": label,
            "before": before_value,
            "after": after_value,
            "changed": (
                before_value
                != after_value
            ),
        })

    before_sans = set(
        _value(
            before,
            "certificate",
            "sans",
        )
        or []
    )

    after_sans = set(
        _value(
            after,
            "certificate",
            "sans",
        )
        or []
    )

    added_sans = sorted(
        after_sans - before_sans
    )

    removed_sans = sorted(
        before_sans - after_sans
    )

    before_headers = (
        _value(
            before,
            "http",
            "security_headers",
        )
        or {}
    )

    after_headers = (
        _value(
            after,
            "http",
            "security_headers",
        )
        or {}
    )

    header_changes = []

    all_headers = sorted(
        set(before_headers)
        | set(after_headers)
    )

    for header in all_headers:
        before_value = before_headers.get(
            header
        )

        after_value = after_headers.get(
            header
        )

        if before_value != after_value:
            header_changes.append({
                "header": header,
                "before": before_value,
                "after": after_value,
            })

    before_score = _value(
        before,
        "assessment",
        "score",
    )

    after_score = _value(
        after,
        "assessment",
        "score",
    )

    score_delta = None

    if (
        isinstance(before_score, int)
        and isinstance(after_score, int)
    ):
        score_delta = (
            after_score - before_score
        )

    changed_rows = [
        row
        for row in rows
        if row["changed"]
    ]

    return {
        "before_target": before.get(
            "target"
        ),
        "after_target": after.get(
            "target"
        ),
        "before_scanned_at": before.get(
            "scanned_at"
        ),
        "after_scanned_at": after.get(
            "scanned_at"
        ),
        "rows": rows,
        "changed_rows": changed_rows,
        "changed_count": (
            len(changed_rows)
            + len(added_sans)
            + len(removed_sans)
            + len(header_changes)
        ),
        "added_sans": added_sans,
        "removed_sans": removed_sans,
        "header_changes": header_changes,
        "score_delta": score_delta,
    }
