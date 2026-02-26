"""Tests for ASI-09 TrustVerifier."""
from __future__ import annotations

import pytest

from aumos_owasp_defenses.defenses.asi09_trust_exploitation.trust_verifier import (
    AgentTrustProfile,
    ClaimVerificationResult,
    DelegationResult,
    EscalationCheckResult,
    TrustTier,
    TrustVerifier,
)


# ---------------------------------------------------------------------------
# TrustTier ordering
# ---------------------------------------------------------------------------


class TestTrustTier:
    def test_ordering(self) -> None:
        assert TrustTier.PUBLIC < TrustTier.LIMITED
        assert TrustTier.LIMITED < TrustTier.STANDARD
        assert TrustTier.STANDARD < TrustTier.ELEVATED
        assert TrustTier.ELEVATED < TrustTier.ADMIN
        assert TrustTier.ADMIN < TrustTier.SYSTEM

    def test_equality(self) -> None:
        assert TrustTier.STANDARD == TrustTier.STANDARD


# ---------------------------------------------------------------------------
# AgentTrustProfile
# ---------------------------------------------------------------------------


class TestAgentTrustProfile:
    def test_default_current_tier_is_public(self) -> None:
        profile = AgentTrustProfile("agent-1", TrustTier.STANDARD)
        assert profile.current_tier == TrustTier.PUBLIC

    def test_custom_current_tier(self) -> None:
        profile = AgentTrustProfile("agent-1", TrustTier.ADMIN, TrustTier.ELEVATED)
        assert profile.current_tier == TrustTier.ELEVATED


# ---------------------------------------------------------------------------
# TrustVerifier — construction
# ---------------------------------------------------------------------------


class TestTrustVerifierConstruction:
    def test_empty_init(self) -> None:
        v = TrustVerifier()
        result = v.verify_claim("unknown", TrustTier.PUBLIC)
        assert result.accepted is False

    def test_init_with_profiles(self) -> None:
        profile = AgentTrustProfile("agent-1", TrustTier.STANDARD)
        v = TrustVerifier([profile])
        result = v.verify_claim("agent-1", TrustTier.STANDARD)
        assert result.accepted is True

    def test_register_profile(self) -> None:
        v = TrustVerifier()
        v.register_profile(AgentTrustProfile("agent-1", TrustTier.ADMIN))
        result = v.verify_claim("agent-1", TrustTier.ADMIN)
        assert result.accepted is True

    def test_register_profile_replaces_existing(self) -> None:
        v = TrustVerifier()
        v.register_profile(AgentTrustProfile("agent-1", TrustTier.LIMITED))
        v.register_profile(AgentTrustProfile("agent-1", TrustTier.ADMIN))
        result = v.verify_claim("agent-1", TrustTier.ADMIN)
        assert result.accepted is True


# ---------------------------------------------------------------------------
# TrustVerifier — verify_claim
# ---------------------------------------------------------------------------


class TestVerifyClaim:
    def setup_method(self) -> None:
        self.verifier = TrustVerifier()
        self.verifier.register_profile(
            AgentTrustProfile("worker", TrustTier.STANDARD, TrustTier.STANDARD)
        )

    def test_claim_at_ceiling_accepted(self) -> None:
        result = self.verifier.verify_claim("worker", TrustTier.STANDARD)
        assert result.accepted is True
        assert result.ceiling_tier == TrustTier.STANDARD
        assert result.claimed_tier == TrustTier.STANDARD

    def test_claim_below_ceiling_accepted(self) -> None:
        result = self.verifier.verify_claim("worker", TrustTier.LIMITED)
        assert result.accepted is True

    def test_claim_above_ceiling_rejected(self) -> None:
        result = self.verifier.verify_claim("worker", TrustTier.ADMIN)
        assert result.accepted is False
        assert "escalation" in result.reason.lower() or "exceeds" in result.reason.lower()

    def test_unregistered_agent_rejected(self) -> None:
        result = self.verifier.verify_claim("ghost", TrustTier.PUBLIC)
        assert result.accepted is False
        assert result.ceiling_tier == TrustTier.PUBLIC

    def test_result_is_frozen(self) -> None:
        result = self.verifier.verify_claim("worker", TrustTier.STANDARD)
        with pytest.raises((AttributeError, TypeError)):
            result.accepted = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TrustVerifier — check_escalation
# ---------------------------------------------------------------------------


class TestCheckEscalation:
    def setup_method(self) -> None:
        self.verifier = TrustVerifier()
        self.verifier.register_profile(
            AgentTrustProfile("agent", TrustTier.ADMIN, TrustTier.STANDARD)
        )

    def test_escalation_detected(self) -> None:
        result = self.verifier.check_escalation("agent", TrustTier.ELEVATED)
        assert result.is_escalation is True
        assert result.delta > 0

    def test_no_escalation_for_same_tier(self) -> None:
        result = self.verifier.check_escalation("agent", TrustTier.STANDARD)
        assert result.is_escalation is False
        assert result.delta == 0

    def test_demotion_not_escalation(self) -> None:
        result = self.verifier.check_escalation("agent", TrustTier.LIMITED)
        assert result.is_escalation is False
        assert result.delta < 0

    def test_unregistered_agent_uses_public_baseline(self) -> None:
        result = self.verifier.check_escalation("ghost", TrustTier.STANDARD)
        assert result.current_tier == TrustTier.PUBLIC
        assert result.is_escalation is True

    def test_result_fields(self) -> None:
        result = self.verifier.check_escalation("agent", TrustTier.ELEVATED)
        assert result.agent_id == "agent"
        assert result.new_tier == TrustTier.ELEVATED
        assert result.current_tier == TrustTier.STANDARD


# ---------------------------------------------------------------------------
# TrustVerifier — update_current_tier
# ---------------------------------------------------------------------------


class TestUpdateCurrentTier:
    def setup_method(self) -> None:
        self.verifier = TrustVerifier()
        self.verifier.register_profile(
            AgentTrustProfile("agent", TrustTier.ELEVATED, TrustTier.LIMITED)
        )

    def test_update_within_ceiling(self) -> None:
        self.verifier.update_current_tier("agent", TrustTier.STANDARD)
        result = self.verifier.check_escalation("agent", TrustTier.STANDARD)
        assert result.current_tier == TrustTier.STANDARD

    def test_update_above_ceiling_raises(self) -> None:
        with pytest.raises(ValueError):
            self.verifier.update_current_tier("agent", TrustTier.ADMIN)

    def test_update_unregistered_raises(self) -> None:
        with pytest.raises(ValueError):
            self.verifier.update_current_tier("ghost", TrustTier.PUBLIC)


# ---------------------------------------------------------------------------
# TrustVerifier — delegate_trust
# ---------------------------------------------------------------------------


class TestDelegateTrust:
    def setup_method(self) -> None:
        self.verifier = TrustVerifier()
        self.verifier.register_profile(
            AgentTrustProfile("admin-agent", TrustTier.ADMIN, TrustTier.ADMIN)
        )
        self.verifier.register_profile(
            AgentTrustProfile("worker-agent", TrustTier.ELEVATED, TrustTier.PUBLIC)
        )

    def test_successful_delegation(self) -> None:
        result = self.verifier.delegate_trust(
            "admin-agent", "worker-agent", TrustTier.STANDARD
        )
        assert result.accepted is True
        assert result.delegated_tier == TrustTier.STANDARD
        # Verify the delegate's current tier was updated
        escalation = self.verifier.check_escalation("worker-agent", TrustTier.STANDARD)
        assert escalation.current_tier == TrustTier.STANDARD

    def test_delegation_denied_equal_tier(self) -> None:
        result = self.verifier.delegate_trust(
            "admin-agent", "worker-agent", TrustTier.ADMIN
        )
        assert result.accepted is False
        assert "may not grant" in result.reason.lower() or "denied" in result.reason.lower()

    def test_delegation_denied_above_delegate_ceiling(self) -> None:
        # worker ceiling is ELEVATED, try to grant ADMIN (> ceiling)
        result = self.verifier.delegate_trust(
            "admin-agent", "worker-agent", TrustTier.ADMIN
        )
        assert result.accepted is False

    def test_unregistered_delegator_denied(self) -> None:
        result = self.verifier.delegate_trust(
            "ghost", "worker-agent", TrustTier.LIMITED
        )
        assert result.accepted is False
        assert "no registered" in result.reason.lower()

    def test_unregistered_delegate_denied(self) -> None:
        result = self.verifier.delegate_trust(
            "admin-agent", "ghost-worker", TrustTier.LIMITED
        )
        assert result.accepted is False
        assert "no registered" in result.reason.lower()

    def test_delegation_result_is_frozen(self) -> None:
        result = self.verifier.delegate_trust(
            "admin-agent", "worker-agent", TrustTier.STANDARD
        )
        with pytest.raises((AttributeError, TypeError)):
            result.accepted = False  # type: ignore[misc]
