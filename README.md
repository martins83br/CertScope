# CertScope

**TLS & Certificate Intelligence Platform**

CertScope is a local-first defensive security application for analyzing TLS certificates, PKI posture, protocol support, HTTPS security configuration, and certificate changes over time.

Rather than acting only as a certificate viewer, CertScope combines live TLS observations, certificate intelligence, historical snapshots, change detection, risk analysis, Certificate Transparency data, evidence generation, and reporting in a single web interface.

## Features

### TLS & Certificate Analysis

- Certificate subject and issuer inspection
- Common Name and Subject Alternative Names
- Certificate validity and expiration analysis
- SHA-256 and SHA-1 fingerprints
- Public-key and signature algorithm inspection
- Independent certificate trust validation
- Independent hostname validation
- Negotiated TLS protocol and cipher
- Active TLS 1.0, 1.1, 1.2 and 1.3 probes
- Explicit protocol states: `SUPPORTED`, `REJECTED`, `INCONCLUSIVE`, and `LOCAL_UNSUPPORTED`

### PKI Intelligence

- Server-supplied certificate chain inspection
- Chain verification status
- Certificate Transparency intelligence
- Publicly observed certificate names
- Historical certificate issuers
- Certificate Authority timeline

Certificate Transparency information is supplemental public intelligence. CT service availability does not affect the validity of the primary TLS and certificate assessment.

### Security Assessment

- Explainable security score and grade
- Certificate expiration findings
- Weak cryptography detection
- Legacy TLS detection
- HTTPS security header inspection
- HSTS analysis
- Content-Security-Policy visibility
- Actionable recommendations

### Historical Intelligence

CertScope stores local snapshots so certificate posture can be compared over time.

- Historical scan records
- Certificate and fingerprint change detection
- Issuer and public-key changes
- SAN changes
- TLS and cipher changes
- Validation changes
- Security score changes
- Certificate Story interpretation
- Risk intelligence events

Historical snapshot compatibility is maintained for earlier CertScope data formats.

### Dashboard & Watchlist

- Certificate health and expiration visibility
- Security score and grade
- Watched vs historical asset distinction
- Risk event summaries
- Recent certificate/security events
- Manual watchlist scanning

The current release does not provide a background scheduler. Watchlist scans are initiated manually from the dashboard.

### Evidence & Reporting

CertScope can generate:

- PDF security reports
- JSON evidence packages
- Snapshot SHA-256 integrity hashes
- Certificate fingerprints
- Scan metadata
- Findings and recommendations
- Change intelligence

## Interface

CertScope includes:

- Dashboard
- Scanner
- History
- Historical snapshot view
- Compare
- Target intelligence view
- PDF report export
- JSON evidence export

## Installation

Python 3.11+ is recommended.

    git clone https://github.com/martins83br/CertScope.git
    cd CertScope

    python3 -m venv .venv
    source .venv/bin/activate

    python -m pip install --upgrade pip
    pip install -r requirements.txt

## Run

    python app.py

Then open:

    http://127.0.0.1:5050

CertScope intentionally binds to the local loopback interface by default.

## Tests

    python -m pytest -q

## Local Data

Runtime data is stored locally under the `data/` directory.

Generated scan snapshots, watchlist data, evidence packages, and PDF reports are excluded from version control.

## Security Model

CertScope is currently designed as a local-first application.

The scanner performs outbound network connections to user-supplied targets. The built-in Flask application therefore binds only to `127.0.0.1`.

Do not expose the application directly to untrusted or public networks.

## Responsible Use

CertScope is designed for defensive, non-intrusive TLS and PKI analysis.

The project does not exploit vulnerabilities, bypass authentication, brute-force credentials, or modify remote systems.

Only analyze systems that you own or are authorized to assess.

## Technology

- Python
- Flask
- cryptography
- requests
- ReportLab
- pytest

## Version

**CertScope v0.8.0**

## Status

CertScope is under active development.

Future releases may expand certificate monitoring, risk intelligence, reporting, and PKI analysis capabilities.
