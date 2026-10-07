from __future__ import annotations


def _grade(score: int) -> str:
    if score >= 98:
        return "A+"
    if score >= 93:
        return "A"
    if score >= 88:
        return "A-"
    if score >= 83:
        return "B+"
    if score >= 78:
        return "B"
    if score >= 73:
        return "B-"
    if score >= 68:
        return "C+"
    if score >= 63:
        return "C"
    if score >= 58:
        return "C-"
    if score >= 50:
        return "D"

    return "F"


def _tls_status(item: dict) -> str:
    status = item.get("status")

    if status:
        return status

    return (
        "SUPPORTED"
        if item.get("supported")
        else "REJECTED"
    )


def assess_scan(scan: dict) -> dict:
    score = 100
    findings = []
    recommendations = []

    validation = scan.get(
        "validation",
        {},
    )

    certificate = scan.get(
        "certificate",
        {},
    )

    http = scan.get(
        "http",
        {},
    )

    if not validation.get(
        "trust_valid",
        False,
    ):
        score -= 35

        findings.append({
            "severity": "CRITICAL",
            "title": "Certificate trust validation failed",
            "detail": (
                validation.get("trust_error")
                or validation.get("error")
                or "The certificate chain could not be trusted."
            ),
        })

        recommendations.append(
            "Review the certificate chain, issuer trust and intermediate certificates."
        )

    if not validation.get(
        "hostname_valid",
        False,
    ):
        score -= 35

        findings.append({
            "severity": "CRITICAL",
            "title": "Certificate hostname mismatch",
            "detail": (
                validation.get(
                    "hostname_error"
                )
                or
                "The certificate identity does not match the requested hostname."
            ),
        })

        recommendations.append(
            "Ensure the requested hostname is included in the certificate SAN extension."
        )

    if certificate.get(
        "not_yet_valid"
    ):
        score -= 30

        findings.append({
            "severity": "HIGH",
            "title": "Certificate is not yet valid",
            "detail": (
                "The certificate validity period has not started."
            ),
        })

    days = certificate.get(
        "days_remaining"
    )

    if certificate.get("expired"):
        score -= 40

        findings.append({
            "severity": "CRITICAL",
            "title": "Certificate expired",
            "detail": (
                f"Certificate expired {abs(days or 0)} day(s) ago."
            ),
        })

        recommendations.append(
            "Replace the expired certificate immediately."
        )

    elif days is not None:
        if days <= 7:
            score -= 30

            findings.append({
                "severity": "HIGH",
                "title": "Certificate expires very soon",
                "detail": (
                    f"Certificate expires in {days} day(s)."
                ),
            })

            recommendations.append(
                "Renew the certificate immediately."
            )

        elif days <= 30:
            score -= 15

            findings.append({
                "severity": "MEDIUM",
                "title": "Certificate renewal approaching",
                "detail": (
                    f"Certificate expires in {days} day(s)."
                ),
            })

            recommendations.append(
                "Plan certificate renewal before the expiration window becomes critical."
            )

        elif days <= 60:
            score -= 5

            findings.append({
                "severity": "LOW",
                "title": "Certificate renewal window",
                "detail": (
                    f"Certificate expires in {days} day(s)."
                ),
            })

    tls_statuses = {
        item.get("name"): _tls_status(item)
        for item in scan.get(
            "tls_versions",
            []
        )
    }

    if tls_statuses.get(
        "TLS 1.0"
    ) == "SUPPORTED":
        score -= 15

        findings.append({
            "severity": "HIGH",
            "title": "TLS 1.0 supported",
            "detail": (
                "The endpoint accepted a TLS 1.0 connection."
            ),
        })

        recommendations.append(
            "Disable TLS 1.0."
        )

    if tls_statuses.get(
        "TLS 1.1"
    ) == "SUPPORTED":
        score -= 10

        findings.append({
            "severity": "MEDIUM",
            "title": "TLS 1.1 supported",
            "detail": (
                "The endpoint accepted a TLS 1.1 connection."
            ),
        })

        recommendations.append(
            "Disable TLS 1.1."
        )

    if tls_statuses.get(
        "TLS 1.2"
    ) == "REJECTED":
        score -= 15

        findings.append({
            "severity": "MEDIUM",
            "title": "TLS 1.2 not accepted",
            "detail": (
                "The endpoint rejected the forced TLS 1.2 handshake."
            ),
        })

    if tls_statuses.get(
        "TLS 1.3"
    ) == "REJECTED":
        score -= 5

        findings.append({
            "severity": "LOW",
            "title": "TLS 1.3 not accepted",
            "detail": (
                "The endpoint rejected the forced TLS 1.3 handshake."
            ),
        })

        recommendations.append(
            "Consider enabling TLS 1.3 when supported by the application stack."
        )

    inconclusive = [
        name
        for name, status
        in tls_statuses.items()
        if status in {
            "INCONCLUSIVE",
            "LOCAL_UNSUPPORTED",
        }
    ]

    if inconclusive:
        findings.append({
            "severity": "INFO",
            "title": "TLS protocol probe incomplete",
            "detail": (
                "No score penalty was applied for inconclusive or locally unsupported probes: "
                + ", ".join(inconclusive)
                + "."
            ),
        })

    public_key = certificate.get(
        "public_key",
        {},
    )

    if (
        public_key.get("type") == "RSA"
        and public_key.get("size", 0) < 2048
    ):
        score -= 20

        findings.append({
            "severity": "HIGH",
            "title": "Weak RSA key",
            "detail": (
                f"RSA key size is {public_key.get('size')} bits."
            ),
        })

        recommendations.append(
            "Use an RSA key of at least 2048 bits or a modern EC key."
        )

    signature = str(
        certificate.get(
            "signature_algorithm",
            ""
        )
    ).lower()

    if "md5" in signature:
        score -= 30

        findings.append({
            "severity": "CRITICAL",
            "title": "MD5 certificate signature",
            "detail": (
                "The certificate uses the obsolete MD5 hash algorithm."
            ),
        })

    elif "sha1" in signature:
        score -= 20

        findings.append({
            "severity": "HIGH",
            "title": "SHA-1 certificate signature",
            "detail": (
                "The certificate uses the deprecated SHA-1 hash algorithm."
            ),
        })

    if http.get("available"):
        if not http.get(
            "hsts_enabled"
        ):
            score -= 5

            findings.append({
                "severity": "LOW",
                "title": "HSTS not detected",
                "detail": (
                    "Strict-Transport-Security was not detected in the HTTPS response."
                ),
            })

            recommendations.append(
                "Consider enabling HSTS after validating HTTPS-only operation."
            )

        headers = http.get(
            "security_headers",
            {},
        )

        if not headers.get(
            "x-content-type-options"
        ):
            findings.append({
                "severity": "INFO",
                "title": "X-Content-Type-Options not detected",
                "detail": (
                    "The response did not include X-Content-Type-Options."
                ),
            })

        if not headers.get(
            "content-security-policy"
        ):
            findings.append({
                "severity": "INFO",
                "title": "Content-Security-Policy not detected",
                "detail": (
                    "The response did not include Content-Security-Policy."
                ),
            })

    score = max(
        0,
        min(100, score),
    )

    if not findings:
        findings.append({
            "severity": "INFO",
            "title": "No immediate TLS issues detected",
            "detail": (
                "The current defensive checks did not identify an immediate certificate or TLS issue."
            ),
        })

    if not recommendations:
        recommendations.append(
            "Continue monitoring certificate lifecycle and TLS configuration for changes."
        )

    return {
        "score": score,
        "grade": _grade(score),
        "findings": findings,
        "recommendations": recommendations,
    }
