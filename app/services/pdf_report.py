from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import (
    TA_CENTER,
    TA_LEFT,
)
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.services.evidence import snapshot_hash


BASE_DIR = Path(__file__).resolve().parents[2]
REPORT_DIR = BASE_DIR / "data" / "reports"


PAGE_WIDTH = 210 * mm


def _safe(value) -> str:
    if value is None:
        return "Not available"

    if isinstance(value, bool):
        return "Yes" if value else "No"

    return escape(str(value))


def _short_hash(value: str | None) -> str:
    if not value:
        return "Not available"

    return value


def _table(
    rows,
    widths=None,
    header=False,
    font_size=8,
):
    table = Table(
        rows,
        colWidths=widths,
        repeatRows=1 if header else 0,
        hAlign="LEFT",
    )

    commands = [
        (
            "VALIGN",
            (0, 0),
            (-1, -1),
            "TOP",
        ),
        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.35,
            colors.HexColor("#D9E2EC"),
        ),
        (
            "LEFTPADDING",
            (0, 0),
            (-1, -1),
            6,
        ),
        (
            "RIGHTPADDING",
            (0, 0),
            (-1, -1),
            6,
        ),
        (
            "TOPPADDING",
            (0, 0),
            (-1, -1),
            6,
        ),
        (
            "BOTTOMPADDING",
            (0, 0),
            (-1, -1),
            6,
        ),
        (
            "FONTSIZE",
            (0, 0),
            (-1, -1),
            font_size,
        ),
    ]

    if header:
        commands.extend([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#0F2740"),
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white,
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold",
            ),
        ])
    else:
        commands.extend([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#F1F5F9"),
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold",
            ),
        ])

    table.setStyle(
        TableStyle(commands)
    )

    return table


def _paragraph_cell(
    value,
    style,
):
    return Paragraph(
        _safe(value),
        style,
    )


def generate_pdf(
    result: dict,
    report_id: str | None = None,
) -> Path:
    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    target = result.get(
        "target",
        "target",
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    safe_target = (
        target
        .replace("/", "_")
        .replace("\\", "_")
    )

    path = (
        REPORT_DIR
        / f"CertScope_{safe_target}_{timestamp}.pdf"
    )

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=17 * mm,
        leftMargin=17 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=(
            f"CertScope Security Report - {target}"
        ),
        author="CertScope",
        subject=(
            "TLS, PKI and Certificate Intelligence"
        ),
    )

    styles = getSampleStyleSheet()

    title = ParagraphStyle(
        "TitleCS",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=27,
        leading=32,
        textColor=colors.HexColor("#102A43"),
        alignment=TA_CENTER,
        spaceAfter=7,
    )

    subtitle = ParagraphStyle(
        "SubtitleCS",
        parent=styles["Normal"],
        fontSize=11,
        leading=16,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#486581"),
        spaceAfter=18,
    )

    section = ParagraphStyle(
        "SectionCS",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=19,
        textColor=colors.HexColor("#102A43"),
        spaceBefore=13,
        spaceAfter=8,
    )

    subsection = ParagraphStyle(
        "SubsectionCS",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#243B53"),
        spaceBefore=9,
        spaceAfter=5,
    )

    body = ParagraphStyle(
        "BodyCS",
        parent=styles["BodyText"],
        fontSize=9,
        leading=14,
        textColor=colors.HexColor("#334E68"),
        spaceAfter=6,
    )

    small = ParagraphStyle(
        "SmallCS",
        parent=body,
        fontSize=7.5,
        leading=10,
    )

    mono = ParagraphStyle(
        "MonoCS",
        parent=small,
        fontName="Courier",
        fontSize=6.5,
        leading=9,
        wordWrap="CJK",
    )

    center_small = ParagraphStyle(
        "CenterSmallCS",
        parent=small,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#627D98"),
    )

    finding_title = ParagraphStyle(
        "FindingTitle",
        parent=body,
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        spaceAfter=2,
    )

    story = []

    assessment = result.get(
        "assessment",
        {},
    )

    certificate = result.get(
        "certificate",
        {},
    )

    connection = result.get(
        "connection",
        {},
    )

    validation = result.get(
        "validation",
        {},
    )

    http = result.get(
        "http",
        {},
    )

    pki = result.get(
        "pki",
        {},
    )

    cert_story = result.get(
        "story",
        {},
    )

    lifecycle = result.get(
        "lifecycle",
        {},
    )

    comparison = result.get(
        "comparison",
        {},
    )

    evidence_hash = snapshot_hash(
        result
    )

    story.extend([
        Spacer(1, 18 * mm),
        Paragraph(
            "CertScope",
            title,
        ),
        Paragraph(
            "TLS &amp; Certificate Intelligence Report",
            subtitle,
        ),
        Spacer(1, 5 * mm),
    ])

    cover_rows = [
        [
            "Target",
            _safe(target),
        ],
        [
            "Scan Time",
            _safe(
                result.get(
                    "scanned_at"
                )
            ),
        ],
        [
            "Security Score",
            (
                f"{assessment.get('score', 'N/A')} / 100"
            ),
        ],
        [
            "Grade",
            _safe(
                assessment.get(
                    "grade"
                )
            ),
        ],
        [
            "Negotiated TLS",
            _safe(
                connection.get(
                    "tls_version"
                )
            ),
        ],
        [
            "Certificate Expires",
            _safe(
                certificate.get(
                    "not_after"
                )
            ),
        ],
    ]

    story.append(
        _table(
            cover_rows,
            widths=[
                48 * mm,
                125 * mm,
            ],
        )
    )

    story.extend([
        Spacer(1, 18 * mm),
        Paragraph(
            (
                "<b>Evidence Snapshot SHA-256</b><br/>"
                + _safe(evidence_hash)
            ),
            mono,
        ),
        Spacer(1, 5 * mm),
        Paragraph(
            (
                "Generated by CertScope on "
                + _safe(
                    datetime.now(
                        timezone.utc
                    ).isoformat()
                )
                + ". This report represents an "
                "automated point-in-time observation."
            ),
            center_small,
        ),
        PageBreak(),
    ])

    story.append(
        Paragraph(
            "Executive Summary",
            section,
        )
    )

    if cert_story:
        story.append(
            Paragraph(
                _safe(
                    cert_story.get(
                        "headline",
                        "Certificate assessment",
                    )
                ),
                subsection,
            )
        )

        for paragraph in cert_story.get(
            "paragraphs",
            [],
        ):
            story.append(
                Paragraph(
                    _safe(paragraph),
                    body,
                )
            )

    summary_rows = [
        [
            "Overall Score",
            (
                f"{assessment.get('score', 'N/A')} / 100"
            ),
        ],
        [
            "Grade",
            assessment.get(
                "grade",
                "N/A",
            ),
        ],
        [
            "Trust Validation",
            (
                "PASS"
                if validation.get(
                    "trust_valid"
                )
                else "FAIL"
            ),
        ],
        [
            "Hostname Validation",
            (
                "PASS"
                if validation.get(
                    "hostname_valid"
                )
                else "FAIL"
            ),
        ],
        [
            "Days Remaining",
            certificate.get(
                "days_remaining",
                "N/A",
            ),
        ],
        [
            "HSTS",
            (
                "Detected"
                if http.get(
                    "hsts_enabled"
                )
                else "Not detected"
            ),
        ],
    ]

    story.append(
        _table(
            summary_rows,
            widths=[
                55 * mm,
                118 * mm,
            ],
        )
    )

    story.append(
        Paragraph(
            "Certificate Lifecycle",
            section,
        )
    )

    if lifecycle.get(
        "available"
    ):
        lifecycle_rows = [
            [
                "Issued",
                lifecycle.get(
                    "issued_friendly"
                ),
            ],
            [
                "Expires",
                lifecycle.get(
                    "expires_friendly"
                ),
            ],
            [
                "Lifecycle Progress",
                (
                    f"{lifecycle.get('progress')}%"
                ),
            ],
            [
                "Days Remaining",
                lifecycle.get(
                    "days_remaining"
                ),
            ],
        ]

        story.append(
            _table(
                lifecycle_rows,
                widths=[
                    55 * mm,
                    118 * mm,
                ],
            )
        )
    else:
        story.append(
            Paragraph(
                "Lifecycle information is unavailable.",
                body,
            )
        )

    story.append(
        Paragraph(
            "Certificate Identity",
            section,
        )
    )

    cert_rows = [
        [
            "Common Name",
            _paragraph_cell(
                certificate.get(
                    "subject_common_name"
                ),
                body,
            ),
        ],
        [
            "Issuer",
            _paragraph_cell(
                certificate.get(
                    "issuer_common_name"
                ),
                body,
            ),
        ],
        [
            "Issuer Organization",
            _paragraph_cell(
                certificate.get(
                    "issuer_organization"
                ),
                body,
            ),
        ],
        [
            "Valid From",
            _paragraph_cell(
                certificate.get(
                    "not_before"
                ),
                body,
            ),
        ],
        [
            "Valid Until",
            _paragraph_cell(
                certificate.get(
                    "not_after"
                ),
                body,
            ),
        ],
        [
            "Public Key",
            _paragraph_cell(
                certificate.get(
                    "public_key",
                    {},
                ).get(
                    "description"
                ),
                body,
            ),
        ],
        [
            "Signature",
            _paragraph_cell(
                certificate.get(
                    "signature_algorithm"
                ),
                body,
            ),
        ],
        [
            "Serial Number",
            _paragraph_cell(
                certificate.get(
                    "serial_number"
                ),
                mono,
            ),
        ],
    ]

    story.append(
        _table(
            cert_rows,
            widths=[
                45 * mm,
                128 * mm,
            ],
        )
    )

    story.append(
        Paragraph(
            "Subject Alternative Names",
            subsection,
        )
    )

    sans = certificate.get(
        "sans",
        [],
    )

    if sans:
        for san in sans:
            story.append(
                Paragraph(
                    "• " + _safe(san),
                    body,
                )
            )
    else:
        story.append(
            Paragraph(
                "No DNS SAN entries detected.",
                body,
            )
        )

    story.append(
        Paragraph(
            "TLS Protocol Intelligence",
            section,
        )
    )

    tls_rows = [
        [
            "Protocol",
            "Status",
            "Cipher",
        ]
    ]

    for item in result.get(
        "tls_versions",
        [],
    ):
        tls_rows.append([
            _safe(
                item.get(
                    "name"
                )
            ),
            (
                item.get("status")
                or (
                    "SUPPORTED"
                    if item.get("supported")
                    else "REJECTED"
                )
            ),
            _safe(
                item.get(
                    "cipher"
                )
            ),
        ])

    story.append(
        _table(
            tls_rows,
            widths=[
                42 * mm,
                42 * mm,
                89 * mm,
            ],
            header=True,
        )
    )

    story.append(
        Paragraph(
            "Negotiated Connection",
            subsection,
        )
    )

    connection_rows = [
        [
            "Protocol",
            connection.get(
                "tls_version"
            ),
        ],
        [
            "Cipher",
            connection.get(
                "cipher"
            ),
        ],
        [
            "Cipher Bits",
            connection.get(
                "cipher_bits"
            ),
        ],
        [
            "HTTP Status",
            http.get(
                "status_code"
            ),
        ],
        [
            "Final URL",
            _paragraph_cell(
                http.get(
                    "final_url"
                ),
                small,
            ),
        ],
        [
            "Server Header",
            http.get(
                "server"
            ),
        ],
    ]

    story.append(
        _table(
            connection_rows,
            widths=[
                45 * mm,
                128 * mm,
            ],
        )
    )

    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "Certificate Chain",
            section,
        )
    )

    chain = pki.get(
        "chain",
        {},
    )

    if chain.get(
        "available"
    ):
        story.append(
            Paragraph(
                (
                    "Server-supplied chain verification: "
                    + (
                        "<b>VERIFIED</b>"
                        if chain.get(
                            "verified"
                        )
                        else "<b>REVIEW</b>"
                    )
                ),
                body,
            )
        )

        for cert in chain.get(
            "certificates",
            [],
        ):
            block = [
                Paragraph(
                    (
                        _safe(
                            cert.get(
                                "role",
                                "CERTIFICATE",
                            )
                        )
                        + " — "
                        + _safe(
                            cert.get(
                                "subject_cn"
                            )
                        )
                    ),
                    subsection,
                ),
                _table(
                    [
                        [
                            "Subject",
                            _paragraph_cell(
                                cert.get(
                                    "subject"
                                ),
                                small,
                            ),
                        ],
                        [
                            "Issuer",
                            _paragraph_cell(
                                cert.get(
                                    "issuer"
                                ),
                                small,
                            ),
                        ],
                        [
                            "Public Key",
                            cert.get(
                                "public_key"
                            ),
                        ],
                        [
                            "Signature",
                            cert.get(
                                "signature_algorithm"
                            ),
                        ],
                        [
                            "Valid Until",
                            cert.get(
                                "not_after"
                            ),
                        ],
                        [
                            "SHA-256",
                            _paragraph_cell(
                                cert.get(
                                    "sha256"
                                ),
                                mono,
                            ),
                        ],
                    ],
                    widths=[
                        38 * mm,
                        135 * mm,
                    ],
                ),
                Spacer(
                    1,
                    4 * mm,
                ),
            ]

            story.append(
                KeepTogether(block)
            )
    else:
        story.append(
            Paragraph(
                _safe(
                    chain.get(
                        "error",
                        "Chain data unavailable.",
                    )
                ),
                body,
            )
        )

    story.append(
        Paragraph(
            "HTTPS Security Headers",
            section,
        )
    )

    header_rows = [
        [
            "Header",
            "Status",
            "Value",
        ]
    ]

    headers = http.get(
        "security_headers",
        {},
    )

    for name in [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]:
        value = headers.get(name)

        header_rows.append([
            name,
            (
                "DETECTED"
                if value
                else "NOT DETECTED"
            ),
            _paragraph_cell(
                value or "—",
                small,
            ),
        ])

    story.append(
        _table(
            header_rows,
            widths=[
                52 * mm,
                34 * mm,
                87 * mm,
            ],
            header=True,
            font_size=7.5,
        )
    )

    story.append(
        Paragraph(
            "Certificate Transparency Intelligence",
            section,
        )
    )

    ct = pki.get(
        "ct",
        {},
    )

    if ct.get(
        "available"
    ):
        ct_summary = [
            [
                "CT Records",
                ct.get(
                    "record_count"
                ),
            ],
            [
                "Observed Names",
                ct.get(
                    "unique_name_count"
                ),
            ],
            [
                "Historical Issuers",
                ct.get(
                    "issuer_count"
                ),
            ],
            [
                "Displayed Records",
                ct.get(
                    "displayed_count"
                ),
            ],
        ]

        story.append(
            _table(
                ct_summary,
                widths=[
                    55 * mm,
                    118 * mm,
                ],
            )
        )

        names = ct.get(
            "discovered_names",
            [],
        )

        if names:
            story.append(
                Paragraph(
                    "Observed Certificate Names",
                    subsection,
                )
            )

            for name in names[:30]:
                story.append(
                    Paragraph(
                        "• " + _safe(name),
                        body,
                    )
                )

            if len(names) > 30:
                story.append(
                    Paragraph(
                        (
                            f"Showing 30 of "
                            f"{len(names)} names."
                        ),
                        small,
                    )
                )

        records = ct.get(
            "records",
            [],
        )

        if records:
            story.append(
                Paragraph(
                    "Recent Public Certificate Records",
                    subsection,
                )
            )

            ct_rows = [
                [
                    "Common Name",
                    "Issuer",
                    "Valid From",
                    "Valid Until",
                ]
            ]

            for record in records[:12]:
                ct_rows.append([
                    _paragraph_cell(
                        record.get(
                            "common_name"
                        ),
                        small,
                    ),
                    _paragraph_cell(
                        record.get(
                            "issuer_name"
                        ),
                        small,
                    ),
                    _paragraph_cell(
                        record.get(
                            "not_before"
                        ),
                        small,
                    ),
                    _paragraph_cell(
                        record.get(
                            "not_after"
                        ),
                        small,
                    ),
                ])

            story.append(
                _table(
                    ct_rows,
                    widths=[
                        35 * mm,
                        62 * mm,
                        38 * mm,
                        38 * mm,
                    ],
                    header=True,
                    font_size=6.5,
                )
            )
    else:
        story.append(
            Paragraph(
                (
                    "Certificate Transparency data "
                    "was unavailable during this scan. "
                    "This does not invalidate the "
                    "certificate or TLS observations."
                ),
                body,
            )
        )

        if ct.get("error"):
            story.append(
                Paragraph(
                    _safe(
                        ct.get(
                            "error"
                        )
                    ),
                    small,
                )
            )

    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "Security Findings",
            section,
        )
    )

    findings = assessment.get(
        "findings",
        [],
    )

    if findings:
        for finding in findings:
            severity = _safe(
                finding.get(
                    "severity"
                )
            )

            story.append(
                Paragraph(
                    (
                        severity
                        + " — "
                        + _safe(
                            finding.get(
                                "title"
                            )
                        )
                    ),
                    finding_title,
                )
            )

            story.append(
                Paragraph(
                    _safe(
                        finding.get(
                            "detail"
                        )
                    ),
                    body,
                )
            )

            story.append(
                Spacer(
                    1,
                    2 * mm,
                )
            )
    else:
        story.append(
            Paragraph(
                "No findings recorded.",
                body,
            )
        )

    story.append(
        Paragraph(
            "Recommendations",
            section,
        )
    )

    recommendations = assessment.get(
        "recommendations",
        [],
    )

    for index, recommendation in enumerate(
        recommendations,
        start=1,
    ):
        story.append(
            Paragraph(
                (
                    f"<b>{index}.</b> "
                    + _safe(
                        recommendation
                    )
                ),
                body,
            )
        )

    story.append(
        Paragraph(
            "Change Intelligence",
            section,
        )
    )

    if comparison:
        story.append(
            Paragraph(
                _safe(
                    comparison.get(
                        "summary",
                        "No comparison summary available.",
                    )
                ),
                body,
            )
        )

        changes = comparison.get(
            "changes",
            [],
        )

        if changes:
            change_rows = [
                [
                    "Category",
                    "Property",
                    "Before",
                    "After",
                ]
            ]

            for change in changes[:20]:
                change_rows.append([
                    _safe(
                        change.get(
                            "category"
                        )
                    ),
                    _safe(
                        change.get(
                            "field"
                        )
                    ),
                    _paragraph_cell(
                        change.get(
                            "before"
                        ),
                        small,
                    ),
                    _paragraph_cell(
                        change.get(
                            "after"
                        ),
                        small,
                    ),
                ])

            story.append(
                _table(
                    change_rows,
                    widths=[
                        30 * mm,
                        40 * mm,
                        51 * mm,
                        52 * mm,
                    ],
                    header=True,
                    font_size=6.5,
                )
            )
    else:
        story.append(
            Paragraph(
                "No previous-scan comparison was recorded.",
                body,
            )
        )

    story.append(
        Paragraph(
            "Evidence & Integrity",
            section,
        )
    )

    evidence_rows = [
        [
            "Report ID",
            report_id or "Not supplied",
        ],
        [
            "Target",
            target,
        ],
        [
            "Scan Timestamp",
            result.get(
                "scanned_at"
            ),
        ],
        [
            "Snapshot SHA-256",
            _paragraph_cell(
                evidence_hash,
                mono,
            ),
        ],
        [
            "Certificate SHA-256",
            _paragraph_cell(
                _short_hash(
                    certificate.get(
                        "sha256_fingerprint"
                    )
                ),
                mono,
            ),
        ],
        [
            "Certificate SHA-1",
            _paragraph_cell(
                _short_hash(
                    certificate.get(
                        "sha1_fingerprint"
                    )
                ),
                mono,
            ),
        ],
        [
            "Serial Number",
            _paragraph_cell(
                certificate.get(
                    "serial_number"
                ),
                mono,
            ),
        ],
    ]

    story.append(
        _table(
            evidence_rows,
            widths=[
                45 * mm,
                128 * mm,
            ],
        )
    )

    story.extend([
        Spacer(
            1,
            10 * mm,
        ),
        Paragraph(
            (
                "<b>Methodology note:</b> CertScope "
                "performs defensive, non-intrusive "
                "observations of publicly presented "
                "TLS certificates, protocol support, "
                "HTTPS response headers and public "
                "Certificate Transparency information. "
                "Results are point-in-time observations "
                "and should not be interpreted as a "
                "complete penetration test."
            ),
            small,
        ),
        Spacer(
            1,
            8 * mm,
        ),
        Paragraph(
            (
                "Generated by CertScope — "
                "TLS &amp; Certificate Intelligence Platform"
            ),
            center_small,
        ),
    ])

    doc.build(story)

    return path
