"""Tests for ASI-06 ProvenanceTracker."""
from __future__ import annotations

import hashlib

import pytest

from aumos_owasp_defenses.defenses.asi06_memory_poisoning.provenance_tracker import (
    ChainVerificationResult,
    ProvenanceRecord,
    ProvenanceTracker,
    SourceTrustLevel,
)


# ---------------------------------------------------------------------------
# SourceTrustLevel ordering
# ---------------------------------------------------------------------------


class TestSourceTrustLevel:
    def test_ordering(self) -> None:
        assert SourceTrustLevel.UNTRUSTED < SourceTrustLevel.EXTERNAL
        assert SourceTrustLevel.EXTERNAL < SourceTrustLevel.VERIFIED
        assert SourceTrustLevel.VERIFIED < SourceTrustLevel.INTERNAL

    def test_comparisons(self) -> None:
        assert SourceTrustLevel.INTERNAL >= SourceTrustLevel.VERIFIED
        assert SourceTrustLevel.UNTRUSTED == SourceTrustLevel.UNTRUSTED


# ---------------------------------------------------------------------------
# ProvenanceTracker — record
# ---------------------------------------------------------------------------


class TestProvenanceTrackerRecord:
    def test_record_bytes_returns_item_id(self) -> None:
        tracker = ProvenanceTracker()
        item_id = tracker.record(b"content", "agent_internal", SourceTrustLevel.INTERNAL)
        assert isinstance(item_id, str)
        assert len(item_id) > 0

    def test_record_str_content(self) -> None:
        tracker = ProvenanceTracker()
        item_id = tracker.record("hello world", "web", SourceTrustLevel.EXTERNAL)
        chain = tracker.get_chain(item_id)
        assert len(chain) == 1

    def test_record_with_explicit_item_id(self) -> None:
        tracker = ProvenanceTracker()
        item_id = tracker.record(b"data", "src", SourceTrustLevel.VERIFIED, item_id="my-id")
        assert item_id == "my-id"

    def test_record_appends_to_existing_chain(self) -> None:
        tracker = ProvenanceTracker()
        item_id = tracker.record(b"v1", "src", SourceTrustLevel.INTERNAL)
        tracker.record(b"v2", "transform", SourceTrustLevel.INTERNAL, item_id=item_id)
        chain = tracker.get_chain(item_id)
        assert len(chain) == 2

    def test_record_second_has_parent_link(self) -> None:
        tracker = ProvenanceTracker()
        item_id = tracker.record(b"v1", "src", SourceTrustLevel.INTERNAL)
        tracker.record(b"v2", "transform", SourceTrustLevel.INTERNAL, item_id=item_id)
        chain = tracker.get_chain(item_id)
        assert chain[0].parent_record_id is None
        assert chain[1].parent_record_id == chain[0].record_id

    def test_record_computes_sha256_hash(self) -> None:
        tracker = ProvenanceTracker()
        content = b"important data"
        item_id = tracker.record(content, "src", SourceTrustLevel.INTERNAL)
        chain = tracker.get_chain(item_id)
        expected = hashlib.sha256(content).hexdigest()
        assert chain[0].content_hash == expected

    def test_record_with_notes(self) -> None:
        tracker = ProvenanceTracker()
        item_id = tracker.record(b"data", "src", SourceTrustLevel.INTERNAL, notes="initial load")
        chain = tracker.get_chain(item_id)
        assert chain[0].notes == "initial load"

    def test_record_has_utc_timestamp(self) -> None:
        from datetime import timezone
        tracker = ProvenanceTracker()
        item_id = tracker.record(b"data", "src", SourceTrustLevel.INTERNAL)
        chain = tracker.get_chain(item_id)
        assert chain[0].recorded_at.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# ProvenanceTracker — get_chain
# ---------------------------------------------------------------------------


class TestGetChain:
    def test_unknown_item_returns_empty_list(self) -> None:
        tracker = ProvenanceTracker()
        assert tracker.get_chain("unknown-id") == []

    def test_chain_is_copy(self) -> None:
        tracker = ProvenanceTracker()
        item_id = tracker.record(b"data", "src", SourceTrustLevel.INTERNAL)
        chain = tracker.get_chain(item_id)
        chain.clear()  # modifying the returned list should not affect the tracker
        assert len(tracker.get_chain(item_id)) == 1


# ---------------------------------------------------------------------------
# ProvenanceTracker — verify_chain
# ---------------------------------------------------------------------------


class TestVerifyChain:
    def test_valid_internal_chain(self) -> None:
        tracker = ProvenanceTracker()
        item_id = tracker.record(b"data", "system", SourceTrustLevel.INTERNAL)
        result = tracker.verify_chain(item_id, SourceTrustLevel.INTERNAL)
        assert result.valid is True
        assert result.chain_length == 1
        assert len(result.violations) == 0

    def test_external_fails_internal_requirement(self) -> None:
        tracker = ProvenanceTracker()
        item_id = tracker.record(b"data", "web", SourceTrustLevel.EXTERNAL)
        result = tracker.verify_chain(item_id, SourceTrustLevel.INTERNAL)
        assert result.valid is False
        assert any("trust" in v.lower() for v in result.violations)

    def test_unknown_item_fails(self) -> None:
        tracker = ProvenanceTracker()
        result = tracker.verify_chain("not-tracked", SourceTrustLevel.EXTERNAL)
        assert result.valid is False
        assert result.chain_length == 0
        assert len(result.violations) > 0

    def test_content_hash_check_pass(self) -> None:
        tracker = ProvenanceTracker()
        content = b"trusted data"
        expected_hash = hashlib.sha256(content).hexdigest()
        item_id = tracker.record(content, "system", SourceTrustLevel.INTERNAL)
        result = tracker.verify_chain(
            item_id,
            SourceTrustLevel.INTERNAL,
            expected_content_hash=expected_hash,
        )
        assert result.valid is True

    def test_content_hash_check_fail(self) -> None:
        tracker = ProvenanceTracker()
        item_id = tracker.record(b"original", "system", SourceTrustLevel.INTERNAL)
        result = tracker.verify_chain(
            item_id,
            SourceTrustLevel.INTERNAL,
            expected_content_hash="wrong_hash_value_that_will_not_match",
        )
        assert result.valid is False
        assert any("hash" in v.lower() for v in result.violations)

    def test_minimum_trust_reported(self) -> None:
        tracker = ProvenanceTracker()
        item_id = tracker.record(b"v1", "system", SourceTrustLevel.INTERNAL)
        tracker.record(b"v2", "web", SourceTrustLevel.EXTERNAL, item_id=item_id)
        result = tracker.verify_chain(item_id, SourceTrustLevel.EXTERNAL)
        assert result.minimum_trust == SourceTrustLevel.EXTERNAL

    def test_required_trust_stored(self) -> None:
        tracker = ProvenanceTracker()
        item_id = tracker.record(b"data", "sys", SourceTrustLevel.VERIFIED)
        result = tracker.verify_chain(item_id, SourceTrustLevel.VERIFIED)
        assert result.required_trust == SourceTrustLevel.VERIFIED


# ---------------------------------------------------------------------------
# ProvenanceTracker — forget and known_items
# ---------------------------------------------------------------------------


class TestForgetAndKnownItems:
    def test_forget_removes_item(self) -> None:
        tracker = ProvenanceTracker()
        item_id = tracker.record(b"data", "src", SourceTrustLevel.INTERNAL)
        tracker.forget(item_id)
        assert tracker.get_chain(item_id) == []

    def test_forget_nonexistent_is_safe(self) -> None:
        tracker = ProvenanceTracker()
        tracker.forget("not-here")  # Should not raise

    def test_known_items_empty(self) -> None:
        tracker = ProvenanceTracker()
        assert tracker.known_items() == []

    def test_known_items_lists_all(self) -> None:
        tracker = ProvenanceTracker()
        id1 = tracker.record(b"a", "src", SourceTrustLevel.INTERNAL)
        id2 = tracker.record(b"b", "src", SourceTrustLevel.EXTERNAL)
        known = tracker.known_items()
        assert id1 in known
        assert id2 in known
        assert len(known) == 2
