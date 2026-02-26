"""Tests for ASI-04 VendorVerifier."""
from __future__ import annotations

import hashlib

import pytest

from aumos_owasp_defenses.defenses.asi04_supply_chain.vendor_verifier import (
    AllowlistEntry,
    VendorVerifier,
    VerificationResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def content() -> bytes:
    return b"tool binary content v1.0"


@pytest.fixture()
def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


@pytest.fixture()
def entry(digest: str) -> AllowlistEntry:
    return AllowlistEntry(
        vendor_id="acme",
        tool_name="search",
        version="1.0.0",
        expected_hash=digest,
    )


@pytest.fixture()
def verifier(entry: AllowlistEntry) -> VendorVerifier:
    return VendorVerifier([entry])


# ---------------------------------------------------------------------------
# AllowlistEntry
# ---------------------------------------------------------------------------


class TestAllowlistEntry:
    def test_default_algorithm(self, entry: AllowlistEntry) -> None:
        assert entry.hash_algorithm == "sha256"

    def test_custom_algorithm(self) -> None:
        e = AllowlistEntry("v", "t", "1.0", "deadbeef", hash_algorithm="sha512")
        assert e.hash_algorithm == "sha512"

    def test_frozen(self, entry: AllowlistEntry) -> None:
        with pytest.raises((AttributeError, TypeError)):
            entry.vendor_id = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# VendorVerifier — construction and allowlist management
# ---------------------------------------------------------------------------


class TestVendorVerifierAllowlist:
    def test_init_empty(self) -> None:
        v = VendorVerifier()
        assert v.list_entries() == []

    def test_init_with_entries(self, entry: AllowlistEntry) -> None:
        v = VendorVerifier([entry])
        assert len(v.list_entries()) == 1

    def test_add_entry(self) -> None:
        v = VendorVerifier()
        e = AllowlistEntry("v", "t", "1.0", "abc123")
        v.add_entry(e)
        assert v.list_entries() == [e]

    def test_add_entry_replaces_existing(self) -> None:
        e1 = AllowlistEntry("v", "t", "1.0", "abc123")
        e2 = AllowlistEntry("v", "t", "1.0", "def456")
        v = VendorVerifier([e1])
        v.add_entry(e2)
        entries = v.list_entries()
        assert len(entries) == 1
        assert entries[0].expected_hash == "def456"

    def test_remove_entry(self, verifier: VendorVerifier, entry: AllowlistEntry) -> None:
        verifier.remove_entry(entry.vendor_id, entry.tool_name, entry.version)
        assert verifier.list_entries() == []

    def test_remove_entry_not_found(self, verifier: VendorVerifier) -> None:
        with pytest.raises(KeyError):
            verifier.remove_entry("missing", "tool", "1.0")

    def test_list_entries_sorted(self) -> None:
        entries = [
            AllowlistEntry("z-vendor", "tool", "1.0", "a"),
            AllowlistEntry("a-vendor", "tool", "1.0", "b"),
            AllowlistEntry("a-vendor", "alpha", "1.0", "c"),
        ]
        v = VendorVerifier(entries)
        result = v.list_entries()
        assert result[0].vendor_id == "a-vendor"
        assert result[0].tool_name == "alpha"
        assert result[-1].vendor_id == "z-vendor"


# ---------------------------------------------------------------------------
# VendorVerifier — verify
# ---------------------------------------------------------------------------


class TestVendorVerifierVerify:
    def test_verify_success(
        self, verifier: VendorVerifier, content: bytes, entry: AllowlistEntry
    ) -> None:
        result = verifier.verify(entry.vendor_id, entry.tool_name, entry.version, content)
        assert result.verified is True
        assert result.vendor_id == entry.vendor_id
        assert result.tool_name == entry.tool_name
        assert result.version == entry.version
        assert result.computed_hash == entry.expected_hash
        assert "passed" in result.reason.lower()

    def test_verify_hash_mismatch(
        self, verifier: VendorVerifier, entry: AllowlistEntry
    ) -> None:
        tampered = b"tampered content"
        result = verifier.verify(entry.vendor_id, entry.tool_name, entry.version, tampered)
        assert result.verified is False
        assert result.expected_hash == entry.expected_hash
        assert result.computed_hash != entry.expected_hash
        assert "mismatch" in result.reason.lower()

    def test_verify_no_allowlist_entry(self, verifier: VendorVerifier) -> None:
        result = verifier.verify("unknown", "tool", "9.9.9", b"data")
        assert result.verified is False
        assert result.expected_hash == ""
        assert "no allowlist entry" in result.reason.lower()
        # Should still compute the hash for the caller to use
        assert result.computed_hash == hashlib.sha256(b"data").hexdigest()

    def test_verify_unsupported_algorithm(self) -> None:
        bad_entry = AllowlistEntry("v", "t", "1.0", "abc123", hash_algorithm="not-real")
        v = VendorVerifier([bad_entry])
        result = v.verify("v", "t", "1.0", b"content")
        assert result.verified is False
        assert "unsupported hash algorithm" in result.reason.lower()
        assert result.computed_hash == ""
        assert result.expected_hash == "abc123"

    def test_verify_returns_correct_timestamp(
        self, verifier: VendorVerifier, content: bytes, entry: AllowlistEntry
    ) -> None:
        from datetime import timezone
        result = verifier.verify(entry.vendor_id, entry.tool_name, entry.version, content)
        assert result.verified_at.tzinfo == timezone.utc

    def test_verify_result_is_frozen(
        self, verifier: VendorVerifier, content: bytes, entry: AllowlistEntry
    ) -> None:
        result = verifier.verify(entry.vendor_id, entry.tool_name, entry.version, content)
        with pytest.raises((AttributeError, TypeError)):
            result.verified = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# VendorVerifier — compute_hash utility
# ---------------------------------------------------------------------------


class TestComputeHash:
    def test_sha256_default(self) -> None:
        data = b"hello world"
        expected = hashlib.sha256(data).hexdigest()
        assert VendorVerifier.compute_hash(data) == expected

    def test_sha512(self) -> None:
        data = b"hello"
        expected = hashlib.sha512(data).hexdigest()
        assert VendorVerifier.compute_hash(data, algorithm="sha512") == expected

    def test_empty_bytes(self) -> None:
        result = VendorVerifier.compute_hash(b"")
        assert isinstance(result, str)
        assert len(result) == 64  # sha256 hex length
