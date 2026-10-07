from __future__ import annotations

import socket
import ssl
import subprocess
from datetime import datetime, timezone

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def _name_to_text(name: x509.Name) -> str:
    parts = []

    for attribute in name:
        key = attribute.oid._name or attribute.oid.dotted_string
        parts.append(f"{key}={attribute.value}")

    return ", ".join(parts)


def _common_name(name: x509.Name) -> str:
    try:
        attributes = name.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )

        if attributes:
            return attributes[0].value
    except Exception:
        pass

    return _name_to_text(name)


def _fingerprint(cert: x509.Certificate) -> str:
    value = cert.fingerprint(hashes.SHA256()).hex().upper()

    return ":".join(
        value[i:i + 2]
        for i in range(0, len(value), 2)
    )


def _key_description(cert: x509.Certificate) -> str:
    key = cert.public_key()

    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}-bit"

    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA {key.curve.name}"

    return key.__class__.__name__


def _certificate_to_dict(
    cert: x509.Certificate,
    position: int,
) -> dict:
    try:
        basic_constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value

        is_ca = basic_constraints.ca

    except x509.ExtensionNotFound:
        is_ca = False

    return {
        "position": position,
        "subject": _name_to_text(cert.subject),
        "subject_cn": _common_name(cert.subject),
        "issuer": _name_to_text(cert.issuer),
        "issuer_cn": _common_name(cert.issuer),
        "serial_number": format(cert.serial_number, "X"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha256": _fingerprint(cert),
        "public_key": _key_description(cert),
        "signature_algorithm": (
            cert.signature_hash_algorithm.name
            if cert.signature_hash_algorithm
            else "Unknown"
        ),
        "is_ca": is_ca,
        "self_signed_name": cert.subject == cert.issuer,
    }


def _extract_pem_certificates(text: str) -> list[x509.Certificate]:
    marker_begin = "-----BEGIN CERTIFICATE-----"
    marker_end = "-----END CERTIFICATE-----"

    certificates = []
    cursor = 0

    while True:
        start = text.find(marker_begin, cursor)

        if start == -1:
            break

        end = text.find(marker_end, start)

        if end == -1:
            break

        end += len(marker_end)

        pem = text[start:end] + "\n"

        try:
            cert = x509.load_pem_x509_certificate(
                pem.encode("ascii")
            )
            certificates.append(cert)
        except Exception:
            pass

        cursor = end

    return certificates


def inspect_certificate_chain(
    hostname: str,
    port: int = 443,
    timeout: int = 8,
) -> dict:
    try:
        command = [
            "openssl",
            "s_client",
            "-showcerts",
            "-servername",
            hostname,
            "-connect",
            f"{hostname}:{port}",
        ]

        completed = subprocess.run(
            command,
            input="",
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        combined = (
            completed.stdout
            + "\n"
            + completed.stderr
        )

        certificates = _extract_pem_certificates(
            combined
        )

        chain = [
            _certificate_to_dict(cert, index)
            for index, cert in enumerate(
                certificates,
                start=1,
            )
        ]

        for index, item in enumerate(chain):
            if index == 0:
                item["role"] = "LEAF"
            elif item["self_signed_name"]:
                item["role"] = "ROOT / TRUST ANCHOR"
            elif index == len(chain) - 1:
                item["role"] = "CHAIN CERTIFICATE"
            else:
                item["role"] = "INTERMEDIATE"

        verify_ok = (
            "Verify return code: 0 (ok)"
            in combined
        )

        if not chain:
            return {
                "available": False,
                "verified": False,
                "certificates": [],
                "error": (
                    "No certificate chain could be extracted "
                    "from the server response."
                ),
            }

        return {
            "available": True,
            "verified": verify_ok,
            "certificates": chain,
            "count": len(chain),
            "error": None,
        }

    except FileNotFoundError:
        return {
            "available": False,
            "verified": False,
            "certificates": [],
            "error": (
                "OpenSSL command-line utility was not found "
                "on this system."
            ),
        }

    except subprocess.TimeoutExpired:
        return {
            "available": False,
            "verified": False,
            "certificates": [],
            "error": "Certificate chain probe timed out.",
        }

    except Exception as exc:
        return {
            "available": False,
            "verified": False,
            "certificates": [],
            "error": str(exc),
        }


def query_certificate_transparency(
    hostname: str,
    timeout: int = 10,
) -> dict:
    query_name = hostname

    if hostname.startswith("www."):
        query_name = hostname[4:]

    url = "https://crt.sh/"

    queries = [
        f"%.{query_name}",
        query_name,
    ]

    errors = []
    data = None
    successful_query = None

    for query in queries:
        try:
            response = requests.get(
                url,
                params={
                    "q": query,
                    "output": "json",
                },
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 "
                        "CertScope/0.6"
                    ),
                    "Accept": "application/json",
                },
                timeout=timeout,
            )

            if response.status_code == 404:
                errors.append(
                    f"{query}: HTTP 404"
                )
                continue

            response.raise_for_status()

            parsed = response.json()

            if isinstance(parsed, list):
                data = parsed
                successful_query = query
                break

            errors.append(
                f"{query}: unexpected response"
            )

        except requests.RequestException as exc:
            errors.append(
                f"{query}: {exc}"
            )

        except ValueError as exc:
            errors.append(
                f"{query}: invalid JSON ({exc})"
            )

    if data is None:
        return {
            "available": False,
            "query": query_name,
            "successful_query": None,
            "record_count": 0,
            "displayed_count": 0,
            "records": [],
            "discovered_names": [],
            "unique_name_count": 0,
            "issuers": [],
            "issuer_count": 0,
            "error": (
                "Certificate Transparency service "
                "was unavailable after fallback "
                "queries. "
                + " | ".join(errors)
            ),
        }

    unique_records = {}
    discovered_names = set()
    issuers = set()

    for item in data:
        record_id = item.get("id")

        identity = (
            item.get("common_name", ""),
            item.get("issuer_name", ""),
            item.get("not_before", ""),
            item.get("not_after", ""),
            item.get("serial_number", ""),
            item.get("name_value", ""),
        )

        key = (
            str(record_id)
            if record_id is not None
            else repr(identity)
        )

        unique_records[key] = item

        issuer_name = item.get(
            "issuer_name"
        )

        if issuer_name:
            issuers.add(
                issuer_name
            )

        name_value = item.get(
            "name_value",
            "",
        )

        for name in name_value.splitlines():
            normalized = (
                name.strip()
                .lower()
                .rstrip(".")
            )

            if normalized:
                discovered_names.add(
                    normalized
                )

    records = list(
        unique_records.values()
    )

    records.sort(
        key=lambda item: (
            item.get("not_before")
            or item.get("entry_timestamp")
            or ""
        ),
        reverse=True,
    )

    normalized_records = []
    seen_records = set()

    for item in records:
        identity = (
            item.get(
                "common_name",
                "",
            ),
            item.get(
                "issuer_name",
                "",
            ),
            item.get(
                "not_before",
                "",
            ),
            item.get(
                "not_after",
                "",
            ),
            item.get(
                "serial_number",
                "",
            ),
        )

        if identity in seen_records:
            continue

        seen_records.add(
            identity
        )

        normalized_records.append({
            "id": item.get("id"),
            "issuer_name": item.get(
                "issuer_name",
                "Unknown",
            ),
            "common_name": item.get(
                "common_name",
                "",
            ),
            "name_value": item.get(
                "name_value",
                "",
            ),
            "not_before": item.get(
                "not_before",
                "",
            ),
            "not_after": item.get(
                "not_after",
                "",
            ),
            "entry_timestamp": item.get(
                "entry_timestamp",
                "",
            ),
            "serial_number": item.get(
                "serial_number",
                "",
            ),
        })

        if len(
            normalized_records
        ) >= 50:
            break

    return {
        "available": True,
        "query": query_name,
        "successful_query": successful_query,
        "record_count": len(records),
        "displayed_count": len(
            normalized_records
        ),
        "records": normalized_records,
        "discovered_names": sorted(
            discovered_names
        ),
        "unique_name_count": len(
            discovered_names
        ),
        "issuers": sorted(
            issuers
        ),
        "issuer_count": len(
            issuers
        ),
        "error": None,
    }

def build_pki_intelligence(
    hostname: str,
    port: int = 443,
) -> dict:
    chain = inspect_certificate_chain(
        hostname,
        port,
    )

    ct = query_certificate_transparency(
        hostname
    )

    return {
        "chain": chain,
        "ct": ct,
        "generated_at": (
            datetime.now(timezone.utc).isoformat()
        ),
    }
