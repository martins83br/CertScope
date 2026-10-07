from app.core.scanner import (
    _dnsname_matches,
    normalize_target,
)


def test_normalize_target_basic():
    assert (
        normalize_target(
            "https://Example.COM/path"
        )
        == "example.com"
    )


def test_dns_exact_match():
    assert _dnsname_matches(
        "example.com",
        "example.com",
    )


def test_dns_exact_mismatch():
    assert not _dnsname_matches(
        "example.com",
        "www.example.com",
    )


def test_dns_wildcard_single_label():
    assert _dnsname_matches(
        "*.example.com",
        "www.example.com",
    )


def test_dns_wildcard_does_not_cross_labels():
    assert not _dnsname_matches(
        "*.example.com",
        "a.b.example.com",
    )


def test_dns_wildcard_does_not_match_apex():
    assert not _dnsname_matches(
        "*.example.com",
        "example.com",
    )


def test_invalid_wildcard():
    assert not _dnsname_matches(
        "www.*.example.com",
        "www.test.example.com",
    )
