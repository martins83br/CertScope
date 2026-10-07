from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


TLS_LABELS = {
    ssl.TLSVersion.TLSv1: "TLS 1.0",
    ssl.TLSVersion.TLSv1_1: "TLS 1.1",
    ssl.TLSVersion.TLSv1_2: "TLS 1.2",
    ssl.TLSVersion.TLSv1_3: "TLS 1.3",
}


def normalize_target(target: str) -> str:
    target = target.strip()

    if not target:
        raise ValueError("Please enter a hostname or URL.")

    if "://" not in target:
        target = f"https://{target}"

    parsed = urlparse(target)
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("Invalid hostname or URL.")

    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized hostname.") from exc

    hostname = hostname.lower().rstrip(".")

    if not hostname:
        raise ValueError("Invalid hostname or URL.")

    return hostname


def _name_to_dict(name: x509.Name) -> dict[str, str]:
    result = {}

    for attribute in name:
        key = attribute.oid._name or attribute.oid.dotted_string
        result[key] = attribute.value

    return result


def _public_key_info(cert: x509.Certificate) -> dict:
    key = cert.public_key()

    if isinstance(key, rsa.RSAPublicKey):
        return {
            "type": "RSA",
            "size": key.key_size,
            "description": f"RSA {key.key_size}-bit",
        }

    if isinstance(key, ec.EllipticCurvePublicKey):
        return {
            "type": "EC",
            "size": key.key_size,
            "curve": key.curve.name,
            "description": f"ECDSA {key.curve.name}",
        }

    return {
        "type": key.__class__.__name__,
        "size": getattr(key, "key_size", 0),
        "description": key.__class__.__name__,
    }


def _fingerprint(cert: x509.Certificate, algorithm) -> str:
    value = cert.fingerprint(algorithm).hex().upper()

    return ":".join(
        value[index:index + 2]
        for index in range(0, len(value), 2)
    )


def _idna_name(value: str) -> str:
    value = value.strip().rstrip(".")

    try:
        return value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return value.lower()


def _dnsname_matches(pattern: str, hostname: str) -> bool:
    pattern = _idna_name(pattern)
    hostname = _idna_name(hostname)

    if not pattern or not hostname:
        return False

    if "*" not in pattern:
        return pattern == hostname

    if not pattern.startswith("*."):
        return False

    if pattern.count("*") != 1:
        return False

    suffix = pattern[2:]

    if not suffix:
        return False

    hostname_parts = hostname.split(".")
    suffix_parts = suffix.split(".")

    return (
        len(hostname_parts) == len(suffix_parts) + 1
        and hostname_parts[1:] == suffix_parts
    )


def _certificate_dns_names(cert: x509.Certificate) -> list[str]:
    try:
        extension = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )

        return list(
            extension.value.get_values_for_type(
                x509.DNSName
            )
        )

    except x509.ExtensionNotFound:
        return []


def _certificate_common_name(cert: x509.Certificate) -> str | None:
    attributes = cert.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME
    )

    if not attributes:
        return None

    return attributes[0].value


def _validate_hostname(
    cert: x509.Certificate,
    hostname: str,
) -> tuple[bool, str | None]:
    sans = _certificate_dns_names(cert)

    if sans:
        if any(
            _dnsname_matches(name, hostname)
            for name in sans
        ):
            return True, None

        return (
            False,
            "Hostname does not match any DNS Subject Alternative Name.",
        )

    common_name = _certificate_common_name(cert)

    if common_name and _dnsname_matches(
        common_name,
        hostname,
    ):
        return True, None

    return (
        False,
        "Hostname does not match the certificate identity.",
    )


def _probe_tls_version(
    hostname: str,
    port: int,
    version: ssl.TLSVersion,
    timeout: float = 4.0,
) -> dict:
    label = TLS_LABELS.get(
        version,
        str(version),
    )

    try:
        context = ssl.SSLContext(
            ssl.PROTOCOL_TLS_CLIENT
        )

        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version

    except (
        ValueError,
        ssl.SSLError,
    ) as exc:
        return {
            "name": label,
            "supported": False,
            "status": "LOCAL_UNSUPPORTED",
            "cipher": None,
            "note": str(exc),
        }

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ) as sock:
            try:
                with context.wrap_socket(
                    sock,
                    server_hostname=hostname,
                ) as tls_socket:
                    cipher = tls_socket.cipher()

                    return {
                        "name": label,
                        "supported": True,
                        "status": "SUPPORTED",
                        "cipher": (
                            cipher[0]
                            if cipher
                            else None
                        ),
                        "note": None,
                    }

            except ssl.SSLError as exc:
                return {
                    "name": label,
                    "supported": False,
                    "status": "REJECTED",
                    "cipher": None,
                    "note": str(exc),
                }

    except (
        socket.timeout,
        TimeoutError,
        ConnectionRefusedError,
        socket.gaierror,
        OSError,
    ) as exc:
        return {
            "name": label,
            "supported": False,
            "status": "INCONCLUSIVE",
            "cipher": None,
            "note": str(exc),
        }


def probe_tls_versions(
    hostname: str,
    port: int = 443,
) -> list[dict]:
    versions = [
        ssl.TLSVersion.TLSv1,
        ssl.TLSVersion.TLSv1_1,
        ssl.TLSVersion.TLSv1_2,
        ssl.TLSVersion.TLSv1_3,
    ]

    return [
        _probe_tls_version(
            hostname,
            port,
            version,
        )
        for version in versions
    ]


def inspect_headers(
    hostname: str,
    timeout: float = 6.0,
) -> dict:
    url = f"https://{hostname}/"

    headers_to_check = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]

    try:
        with requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
            headers={
                "User-Agent":
                    "CertScope/0.8 Defensive TLS Assessment"
            },
        ) as response:
            raw = {
                key.lower(): value
                for key, value
                in response.headers.items()
            }

            security_headers = {
                header: raw.get(header)
                for header in headers_to_check
            }

            hsts = raw.get(
                "strict-transport-security"
            )

            return {
                "available": True,
                "status_code": response.status_code,
                "final_url": response.url,
                "server": raw.get("server"),
                "hsts_enabled": bool(hsts),
                "hsts_value": hsts,
                "security_headers": security_headers,
            }

    except requests.RequestException as exc:
        return {
            "available": False,
            "error": str(exc),
            "status_code": None,
            "final_url": url,
            "server": None,
            "hsts_enabled": False,
            "hsts_value": None,
            "security_headers": {},
        }


def _retrieve_certificate_unverified(
    hostname: str,
    port: int,
    timeout: float,
) -> tuple[bytes, str | None, tuple | None]:
    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_CLIENT
    )

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection(
        (hostname, port),
        timeout=timeout,
    ) as sock:
        with context.wrap_socket(
            sock,
            server_hostname=hostname,
        ) as tls_socket:
            der_cert = tls_socket.getpeercert(
                binary_form=True
            )

            return (
                der_cert,
                tls_socket.version(),
                tls_socket.cipher(),
            )


def scan_certificate(
    target: str,
    port: int = 443,
    timeout: float = 8.0,
) -> dict:
    hostname = normalize_target(target)

    trust_valid = False
    trust_error = None
    der_cert = None
    negotiated_tls = None
    cipher = None

    trust_context = ssl.create_default_context()
    trust_context.check_hostname = False
    trust_context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ) as sock:
            with trust_context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as tls_socket:
                der_cert = tls_socket.getpeercert(
                    binary_form=True
                )

                negotiated_tls = tls_socket.version()
                cipher = tls_socket.cipher()
                trust_valid = True

    except ssl.SSLCertVerificationError as exc:
        trust_error = str(exc)

        (
            der_cert,
            negotiated_tls,
            cipher,
        ) = _retrieve_certificate_unverified(
            hostname,
            port,
            timeout,
        )

    if not der_cert:
        raise RuntimeError(
            "The server did not provide a certificate."
        )

    cert = x509.load_der_x509_certificate(
        der_cert
    )

    hostname_valid, hostname_error = (
        _validate_hostname(
            cert,
            hostname,
        )
    )

    now = datetime.now(timezone.utc)

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    seconds_remaining = (
        not_after - now
    ).total_seconds()

    days_remaining = int(
        seconds_remaining // 86400
    )

    expired = now > not_after
    not_yet_valid = now < not_before

    sans = _certificate_dns_names(cert)

    subject = _name_to_dict(
        cert.subject
    )

    issuer = _name_to_dict(
        cert.issuer
    )

    public_key = _public_key_info(
        cert
    )

    pem = cert.public_bytes(
        serialization.Encoding.PEM
    ).decode("ascii")

    try:
        signature_hash = (
            cert.signature_hash_algorithm.name
            if cert.signature_hash_algorithm
            else "Unknown"
        )
    except Exception:
        signature_hash = "Unknown"

    tls_versions = probe_tls_versions(
        hostname,
        port,
    )

    headers = inspect_headers(
        hostname
    )

    sha256 = _fingerprint(
        cert,
        hashes.SHA256(),
    )

    sha1 = _fingerprint(
        cert,
        hashes.SHA1(),
    )

    return {
        "target": hostname,
        "port": port,
        "scanned_at": now.isoformat(),

        "validation": {
            "trust_valid": trust_valid,
            "hostname_valid": hostname_valid,

            # Legacy compatibility
            "error": trust_error,

            "trust_error": trust_error,
            "hostname_error": hostname_error,
        },

        "certificate": {
            "subject": subject,
            "issuer": issuer,

            "subject_common_name": (
                subject.get("commonName")
            ),

            "issuer_common_name": (
                issuer.get("commonName")
            ),

            "issuer_organization": (
                issuer.get("organizationName")
            ),

            "serial_number": format(
                cert.serial_number,
                "X",
            ),

            "not_before": (
                not_before.isoformat()
            ),

            "not_after": (
                not_after.isoformat()
            ),

            "days_remaining": (
                days_remaining
            ),

            "expired": expired,

            "not_yet_valid": (
                not_yet_valid
            ),

            "sans": sans,

            "public_key": public_key,

            "signature_algorithm": (
                signature_hash
            ),

            "fingerprints": {
                "sha256": sha256,
                "sha1": sha1,
            },

            # Compatibility with older modules.
            "sha256_fingerprint": sha256,
            "sha1_fingerprint": sha1,

            "pem": pem,
        },

        "connection": {
            "tls_version": (
                negotiated_tls
                or "Unknown"
            ),

            "cipher": (
                cipher[0]
                if cipher
                else None
            ),
        },

        "tls_versions": tls_versions,

        "http": headers,
    }
