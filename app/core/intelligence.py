from __future__ import annotations


def compare_scans(previous: dict | None, current: dict) -> dict:
    if not previous:
        return {
            "available": False,
            "changed": False,
            "changes": [],
            "summary": "This is the first recorded scan for this target.",
        }

    changes = []

    previous_cert = previous.get("certificate", {})
    current_cert = current.get("certificate", {})

    previous_connection = previous.get("connection", {})
    current_connection = current.get("connection", {})

    previous_validation = previous.get("validation", {})
    current_validation = current.get("validation", {})

    def add_change(
        category: str,
        field: str,
        before,
        after,
        severity: str = "INFO",
    ):
        changes.append({
            "category": category,
            "field": field,
            "before": before,
            "after": after,
            "severity": severity,
        })

    if previous_cert.get("sha256") != current_cert.get("sha256"):
        add_change(
            "Certificate",
            "Certificate fingerprint",
            previous_cert.get("sha256"),
            current_cert.get("sha256"),
            "NOTICE",
        )

    if previous_cert.get("issuer_common_name") != current_cert.get("issuer_common_name"):
        add_change(
            "Certificate",
            "Issuer",
            previous_cert.get("issuer_common_name"),
            current_cert.get("issuer_common_name"),
            "NOTICE",
        )

    if previous_cert.get("issuer_organization") != current_cert.get("issuer_organization"):
        add_change(
            "Certificate",
            "Issuer organization",
            previous_cert.get("issuer_organization"),
            current_cert.get("issuer_organization"),
            "NOTICE",
        )

    if previous_cert.get("serial_number") != current_cert.get("serial_number"):
        add_change(
            "Certificate",
            "Serial number",
            previous_cert.get("serial_number"),
            current_cert.get("serial_number"),
            "NOTICE",
        )

    if previous_cert.get("not_after") != current_cert.get("not_after"):
        add_change(
            "Certificate",
            "Expiration date",
            previous_cert.get("not_after"),
            current_cert.get("not_after"),
        )

    previous_key = previous_cert.get("public_key", {})
    current_key = current_cert.get("public_key", {})

    if previous_key.get("description") != current_key.get("description"):
        add_change(
            "Cryptography",
            "Public key",
            previous_key.get("description"),
            current_key.get("description"),
            "NOTICE",
        )

    previous_sans = set(previous_cert.get("sans", []))
    current_sans = set(current_cert.get("sans", []))

    added_sans = sorted(current_sans - previous_sans)
    removed_sans = sorted(previous_sans - current_sans)

    for san in added_sans:
        add_change(
            "Certificate",
            "SAN added",
            None,
            san,
            "NOTICE",
        )

    for san in removed_sans:
        add_change(
            "Certificate",
            "SAN removed",
            san,
            None,
            "NOTICE",
        )

    if previous_connection.get("tls_version") != current_connection.get("tls_version"):
        add_change(
            "TLS",
            "Negotiated TLS",
            previous_connection.get("tls_version"),
            current_connection.get("tls_version"),
            "NOTICE",
        )

    if previous_connection.get("cipher") != current_connection.get("cipher"):
        add_change(
            "TLS",
            "Negotiated cipher",
            previous_connection.get("cipher"),
            current_connection.get("cipher"),
        )

    if previous_validation.get("trust_valid") != current_validation.get("trust_valid"):
        add_change(
            "Validation",
            "Certificate trust",
            previous_validation.get("trust_valid"),
            current_validation.get("trust_valid"),
            "WARNING",
        )

    if previous_validation.get("hostname_valid") != current_validation.get("hostname_valid"):
        add_change(
            "Validation",
            "Hostname validation",
            previous_validation.get("hostname_valid"),
            current_validation.get("hostname_valid"),
            "WARNING",
        )

    previous_score = previous.get("assessment", {}).get("score")
    current_score = current.get("assessment", {}).get("score")

    if previous_score != current_score:
        add_change(
            "Assessment",
            "Security score",
            previous_score,
            current_score,
        )

    return {
        "available": True,
        "changed": bool(changes),
        "changes": changes,
        "previous_scanned_at": previous.get("scanned_at"),
        "summary": (
            f"{len(changes)} change(s) detected since the previous scan."
            if changes
            else "No material changes detected since the previous scan."
        ),
    }


def build_certificate_story(
    previous: dict | None,
    current: dict,
    comparison: dict,
) -> dict:
    cert = current["certificate"]
    validation = current["validation"]
    assessment = current["assessment"]

    headline = "Certificate posture appears stable."
    level = "NORMAL"

    paragraphs = []

    if not validation.get("trust_valid"):
        headline = "Certificate trust validation requires attention."
        level = "CRITICAL"
        paragraphs.append(
            "The certificate presented by the target could not be validated "
            "against the local trusted certificate authorities."
        )

    elif not validation.get("hostname_valid"):
        headline = "Certificate identity mismatch detected."
        level = "CRITICAL"
        paragraphs.append(
            "The certificate identity does not match the hostname that was scanned."
        )

    elif not previous:
        headline = "Baseline certificate snapshot created."
        level = "BASELINE"
        paragraphs.append(
            "This is the first CertScope snapshot recorded for this target. "
            "Future scans can now be compared against this baseline."
        )

    elif comparison["changed"]:
        cert_changed = any(
            item["field"] == "Certificate fingerprint"
            for item in comparison["changes"]
        )

        issuer_changed = any(
            item["field"] in {"Issuer", "Issuer organization"}
            for item in comparison["changes"]
        )

        key_changed = any(
            item["field"] == "Public key"
            for item in comparison["changes"]
        )

        san_changes = [
            item for item in comparison["changes"]
            if item["field"] in {"SAN added", "SAN removed"}
        ]

        if cert_changed:
            headline = "Certificate rotation or replacement detected."
            level = "CHANGE"

            paragraphs.append(
                "The SHA-256 certificate fingerprint changed since the previous scan, "
                "which indicates that the server is presenting a different certificate."
            )

        if issuer_changed:
            paragraphs.append(
                "The issuing certificate authority information also changed. "
                "This may represent a normal CA migration or certificate lifecycle event."
            )

        if key_changed:
            paragraphs.append(
                "The public-key characteristics changed with the certificate. "
                "Key rotation is commonly expected during certificate replacement."
            )

        if san_changes:
            paragraphs.append(
                "The certificate identity scope changed because one or more "
                "Subject Alternative Names were added or removed."
            )

        if not cert_changed:
            paragraphs.append(
                "The certificate itself appears unchanged, but other observed "
                "TLS or assessment properties changed."
            )

    else:
        paragraphs.append(
            "The current certificate fingerprint, identity and key properties "
            "match the previous recorded scan."
        )

    if cert["days_remaining"] <= 30:
        paragraphs.append(
            f"The certificate expires in {cert['days_remaining']} day(s), "
            "so renewal should be tracked closely."
        )

    elif cert["days_remaining"] <= 60:
        paragraphs.append(
            f"The certificate currently has {cert['days_remaining']} day(s) "
            "remaining before expiration."
        )

    if assessment["score"] >= 93:
        paragraphs.append(
            "The current automated assessment indicates a strong overall "
            "certificate and TLS posture."
        )

    elif assessment["score"] >= 78:
        paragraphs.append(
            "The current posture is generally healthy, although the findings "
            "section contains opportunities for improvement."
        )

    else:
        paragraphs.append(
            "The current score indicates that one or more findings should be "
            "reviewed before treating the configuration as healthy."
        )

    return {
        "headline": headline,
        "level": level,
        "paragraphs": paragraphs,
    }
