from __future__ import annotations

from datetime import datetime, timezone


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _get(data, *keys):
    current = data

    for key in keys:
        if not isinstance(current, dict):
            return None

        current = current.get(key)

    return current


def _event(
    event_type,
    severity,
    title,
    detail,
    before=None,
    after=None,
):
    return {
        "type": event_type,
        "severity": severity,
        "title": title,
        "detail": detail,
        "before": before,
        "after": after,
    }


def expiration_band(days):
    if days is None:
        return "UNKNOWN"

    if days <= 1:
        return "1_DAY"

    if days <= 7:
        return "7_DAYS"

    if days <= 14:
        return "14_DAYS"

    if days <= 30:
        return "30_DAYS"

    if days <= 60:
        return "60_DAYS"

    return "HEALTHY"


def expiration_severity(days):
    if days is None:
        return "INFO"

    if days <= 7:
        return "CRITICAL"

    if days <= 14:
        return "HIGH"

    if days <= 30:
        return "MEDIUM"

    if days <= 60:
        return "LOW"

    return "INFO"


def expiration_message(days):
    if days is None:
        return "Certificate expiration could not be determined."

    if days <= 0:
        return "Certificate is expired or expires today."

    if days == 1:
        return "Certificate expires within 1 day."

    return f"Certificate expires in {days} days."


def build_risk_events(previous, current):
    events = []

    current_days = _get(
        current,
        "certificate",
        "days_remaining",
    )

    current_band = expiration_band(
        current_days
    )

    if previous is None:
        events.append(
            _event(
                "BASELINE_CREATED",
                "INFO",
                "Baseline created",
                "The first local certificate snapshot was recorded for this target.",
            )
        )

        if current_band != "HEALTHY":
            events.append(
                _event(
                    "EXPIRATION_ALERT",
                    expiration_severity(
                        current_days
                    ),
                    "Certificate renewal window",
                    expiration_message(
                        current_days
                    ),
                    None,
                    current_days,
                )
            )

        return events

    previous_days = _get(
        previous,
        "certificate",
        "days_remaining",
    )

    previous_band = expiration_band(
        previous_days
    )

    previous_risk = previous.get(
        "risk_intelligence",
        {},
    )

    previous_event_types = {
        event.get("type")
        for event in previous_risk.get(
            "events",
            [],
        )
    }

    baseline_exists = bool(
        previous_event_types
        & {
            "BASELINE_CREATED",
            "RISK_BASELINE_CREATED",
        }
    )

    if not baseline_exists:
        events.append(
            _event(
                "RISK_BASELINE_CREATED",
                "INFO",
                "Risk intelligence baseline created",
                "CertScope Risk Intelligence is now tracking certificate, identity, TLS, score and expiration changes for this target.",
            )
        )

        if current_band != "HEALTHY":
            events.append(
                _event(
                    "EXPIRATION_ALERT",
                    expiration_severity(
                        current_days
                    ),
                    "Certificate renewal window",
                    expiration_message(
                        current_days
                    ),
                    previous_days,
                    current_days,
                )
            )

    previous_fingerprint = _get(
        previous,
        "certificate",
        "sha256",
    )

    current_fingerprint = _get(
        current,
        "certificate",
        "sha256",
    )

    if (
        previous_fingerprint
        and current_fingerprint
        and previous_fingerprint
        != current_fingerprint
    ):
        events.append(
            _event(
                "CERTIFICATE_ROTATED",
                "INFO",
                "Certificate rotation detected",
                "The SHA-256 certificate fingerprint changed since the previous observation.",
                previous_fingerprint,
                current_fingerprint,
            )
        )

    previous_issuer = _get(
        previous,
        "certificate",
        "issuer_common_name",
    )

    current_issuer = _get(
        current,
        "certificate",
        "issuer_common_name",
    )

    if previous_issuer != current_issuer:
        events.append(
            _event(
                "ISSUER_CHANGED",
                "LOW",
                "Certificate issuer changed",
                "The certificate authority identity changed since the previous observation.",
                previous_issuer,
                current_issuer,
            )
        )

    previous_key = _get(
        previous,
        "certificate",
        "public_key",
        "description",
    )

    current_key = _get(
        current,
        "certificate",
        "public_key",
        "description",
    )

    if previous_key != current_key:
        events.append(
            _event(
                "PUBLIC_KEY_CHANGED",
                "LOW",
                "Public key changed",
                "The certificate public-key characteristics changed.",
                previous_key,
                current_key,
            )
        )

    previous_sans = set(
        _get(
            previous,
            "certificate",
            "sans",
        )
        or []
    )

    current_sans = set(
        _get(
            current,
            "certificate",
            "sans",
        )
        or []
    )

    for san in sorted(
        current_sans - previous_sans
    ):
        events.append(
            _event(
                "SAN_ADDED",
                "INFO",
                "Certificate identity added",
                "A Subject Alternative Name was added to the certificate.",
                None,
                san,
            )
        )

    for san in sorted(
        previous_sans - current_sans
    ):
        events.append(
            _event(
                "SAN_REMOVED",
                "MEDIUM",
                "Certificate identity removed",
                "A Subject Alternative Name was removed from the certificate.",
                san,
                None,
            )
        )

    previous_tls = _get(
        previous,
        "connection",
        "tls_version",
    )

    current_tls = _get(
        current,
        "connection",
        "tls_version",
    )

    if previous_tls != current_tls:
        events.append(
            _event(
                "TLS_CHANGED",
                "LOW",
                "Negotiated TLS changed",
                "The negotiated TLS protocol changed between observations.",
                previous_tls,
                current_tls,
            )
        )

    previous_cipher = _get(
        previous,
        "connection",
        "cipher",
    )

    current_cipher = _get(
        current,
        "connection",
        "cipher",
    )

    if previous_cipher != current_cipher:
        events.append(
            _event(
                "CIPHER_CHANGED",
                "INFO",
                "Negotiated cipher changed",
                "The negotiated TLS cipher changed between observations.",
                previous_cipher,
                current_cipher,
            )
        )

    previous_trust = _get(
        previous,
        "validation",
        "trust_valid",
    )

    current_trust = _get(
        current,
        "validation",
        "trust_valid",
    )

    if (
        previous_trust is not False
        and current_trust is False
    ):
        events.append(
            _event(
                "TRUST_FAILED",
                "CRITICAL",
                "Certificate trust failed",
                "The certificate no longer passes trust validation.",
                previous_trust,
                current_trust,
            )
        )

    previous_hostname = _get(
        previous,
        "validation",
        "hostname_valid",
    )

    current_hostname = _get(
        current,
        "validation",
        "hostname_valid",
    )

    if (
        previous_hostname is not False
        and current_hostname is False
    ):
        events.append(
            _event(
                "HOSTNAME_FAILED",
                "CRITICAL",
                "Hostname validation failed",
                "The certificate identity no longer matches the requested hostname.",
                previous_hostname,
                current_hostname,
            )
        )

    previous_score = _get(
        previous,
        "assessment",
        "score",
    )

    current_score = _get(
        current,
        "assessment",
        "score",
    )

    if (
        isinstance(previous_score, int)
        and isinstance(current_score, int)
        and previous_score != current_score
    ):
        delta = (
            current_score
            - previous_score
        )

        if delta <= -20:
            severity = "HIGH"
        elif delta <= -10:
            severity = "MEDIUM"
        elif delta < 0:
            severity = "LOW"
        else:
            severity = "INFO"

        sign = (
            "+"
            if delta > 0
            else ""
        )

        events.append(
            _event(
                "SCORE_CHANGED",
                severity,
                "Security score changed",
                f"Security score changed from {previous_score} to {current_score} ({sign}{delta}).",
                previous_score,
                current_score,
            )
        )

    if (
        current_band != previous_band
        and current_band != "HEALTHY"
    ):
        events.append(
            _event(
                "EXPIRATION_THRESHOLD",
                expiration_severity(
                    current_days
                ),
                "Expiration threshold crossed",
                f"The certificate moved from {previous_band} to {current_band}. {expiration_message(current_days)}",
                previous_days,
                current_days,
            )
        )

    events.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(
                item["severity"],
                0,
            )
        ),
        reverse=True,
    )

    return events


def summarize_risk_events(events):
    counts = {
        "INFO": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for event in events:
        severity = event.get(
            "severity",
            "INFO",
        )

        if severity in counts:
            counts[severity] += 1

    highest = "INFO"

    for severity in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    ]:
        if counts[severity]:
            highest = severity
            break

    return {
        "count": len(events),
        "counts": counts,
        "highest_severity": highest,
    }


def build_risk_intelligence(
    previous,
    current,
):
    events = build_risk_events(
        previous,
        current,
    )

    return {
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "events": events,
        "summary": summarize_risk_events(
            events
        ),
    }
