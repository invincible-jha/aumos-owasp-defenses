"""Unit tests for ASI-03: Identity and Privilege Compromise — CapabilityChecker.

Tests cover:
- Allowed tool access (direct allowlist and namespace)
- Denied tool access (explicit deny list, out-of-scope, no profile)
- Deny list takes precedence over allowlist
- Dynamic grant / revoke
- Logging side effects (smoke, not asserted on value)
"""
from __future__ import annotations

import pytest

from aumos_owasp_defenses.defenses.asi03_identity_privilege.capability_checker import (
    AgentCapabilityProfile,
    CapabilityChecker,
    PermissionResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def basic_profile() -> AgentCapabilityProfile:
    return AgentCapabilityProfile(
        agent_id="customer-agent",
        allowed_tools={"search_products", "get_order_status"},
        allowed_namespaces=set(),
        deny_tools=set(),
    )


@pytest.fixture()
def namespace_profile() -> AgentCapabilityProfile:
    return AgentCapabilityProfile(
        agent_id="crm-agent",
        allowed_tools=set(),
        allowed_namespaces={"crm", "reporting"},
        deny_tools=set(),
    )


@pytest.fixture()
def checker(basic_profile: AgentCapabilityProfile) -> CapabilityChecker:
    return CapabilityChecker([basic_profile])


@pytest.fixture()
def namespace_checker(namespace_profile: AgentCapabilityProfile) -> CapabilityChecker:
    return CapabilityChecker([namespace_profile])


# ---------------------------------------------------------------------------
# Positive tests — allowed tool access
# ---------------------------------------------------------------------------


class TestAllowedToolAccess:
    def test_explicitly_allowed_tool_is_permitted(self, checker: CapabilityChecker) -> None:
        result = checker.check_permission("customer-agent", "search_products")
        assert result.allowed is True

    def test_second_allowed_tool_is_permitted(self, checker: CapabilityChecker) -> None:
        result = checker.check_permission("customer-agent", "get_order_status")
        assert result.allowed is True

    def test_result_reflects_agent_id(self, checker: CapabilityChecker) -> None:
        result = checker.check_permission("customer-agent", "search_products")
        assert result.agent_id == "customer-agent"

    def test_result_reflects_tool_name(self, checker: CapabilityChecker) -> None:
        result = checker.check_permission("customer-agent", "search_products")
        assert result.tool_name == "search_products"

    def test_allowed_result_has_informative_reason(self, checker: CapabilityChecker) -> None:
        result = checker.check_permission("customer-agent", "search_products")
        assert len(result.reason) > 0

    def test_namespace_permission_grants_access_to_namespaced_tool(
        self, namespace_checker: CapabilityChecker
    ) -> None:
        result = namespace_checker.check_permission("crm-agent", "crm.get_contact")
        assert result.allowed is True

    def test_namespace_permission_mentions_namespace_in_reason(
        self, namespace_checker: CapabilityChecker
    ) -> None:
        result = namespace_checker.check_permission("crm-agent", "crm.update_contact")
        assert "crm" in result.reason

    def test_second_namespace_also_permitted(
        self, namespace_checker: CapabilityChecker
    ) -> None:
        result = namespace_checker.check_permission("crm-agent", "reporting.generate_report")
        assert result.allowed is True

    def test_multiple_agents_with_separate_profiles(self) -> None:
        checker = CapabilityChecker([
            AgentCapabilityProfile("agent-a", allowed_tools={"tool_x"}),
            AgentCapabilityProfile("agent-b", allowed_tools={"tool_y"}),
        ])
        assert checker.check_permission("agent-a", "tool_x").allowed is True
        assert checker.check_permission("agent-b", "tool_y").allowed is True
        assert checker.check_permission("agent-a", "tool_y").allowed is False


# ---------------------------------------------------------------------------
# Negative tests — denied tool access
# ---------------------------------------------------------------------------


class TestDeniedToolAccess:
    def test_tool_not_in_allowlist_is_denied(self, checker: CapabilityChecker) -> None:
        result = checker.check_permission("customer-agent", "delete_database")
        assert result.allowed is False

    def test_unregistered_agent_is_denied(self, checker: CapabilityChecker) -> None:
        result = checker.check_permission("unknown-agent", "search_products")
        assert result.allowed is False

    def test_unregistered_agent_denial_reason_mentions_profile(
        self, checker: CapabilityChecker
    ) -> None:
        result = checker.check_permission("ghost-agent", "any_tool")
        assert "ghost-agent" in result.reason

    def test_namespace_tool_without_namespace_permission_is_denied(
        self, checker: CapabilityChecker
    ) -> None:
        result = checker.check_permission("customer-agent", "admin.delete_all")
        assert result.allowed is False

    def test_tool_without_dot_in_namespace_profile_is_denied(
        self, namespace_checker: CapabilityChecker
    ) -> None:
        # Tool with no dot cannot match namespace check.
        result = namespace_checker.check_permission("crm-agent", "plain_tool")
        assert result.allowed is False

    def test_denied_result_has_informative_reason(self, checker: CapabilityChecker) -> None:
        result = checker.check_permission("customer-agent", "admin_tool")
        assert len(result.reason) > 0

    def test_deny_list_overrides_allowlist(self) -> None:
        profile = AgentCapabilityProfile(
            agent_id="agent",
            allowed_tools={"search_web"},
            deny_tools={"search_web"},
        )
        checker = CapabilityChecker([profile])
        result = checker.check_permission("agent", "search_web")
        assert result.allowed is False

    def test_deny_list_overrides_namespace(self) -> None:
        profile = AgentCapabilityProfile(
            agent_id="agent",
            allowed_namespaces={"crm"},
            deny_tools={"crm.delete_all"},
        )
        checker = CapabilityChecker([profile])
        result = checker.check_permission("agent", "crm.delete_all")
        assert result.allowed is False

    def test_deny_list_reason_mentions_tool(self) -> None:
        profile = AgentCapabilityProfile(
            agent_id="agent",
            deny_tools={"forbidden_tool"},
        )
        checker = CapabilityChecker([profile])
        result = checker.check_permission("agent", "forbidden_tool")
        assert "forbidden_tool" in result.reason

    def test_privilege_escalation_attempt_denied(self) -> None:
        """An agent claiming admin tool access must be denied."""
        profile = AgentCapabilityProfile(
            agent_id="low-privilege-agent",
            allowed_tools={"read_config"},
        )
        checker = CapabilityChecker([profile])
        result = checker.check_permission("low-privilege-agent", "admin.modify_config")
        assert result.allowed is False

    def test_confused_deputy_attack_denied(self) -> None:
        """An agent must not gain access to another agent's tools."""
        checker = CapabilityChecker([
            AgentCapabilityProfile("restricted-agent", allowed_tools={"basic_search"}),
        ])
        result = checker.check_permission("restricted-agent", "super_admin_tool")
        assert result.allowed is False


# ---------------------------------------------------------------------------
# Dynamic grant / revoke
# ---------------------------------------------------------------------------


class TestDynamicGrantRevoke:
    def test_grant_tool_permits_new_tool(self, checker: CapabilityChecker) -> None:
        checker.grant_tool("customer-agent", "send_notification")
        result = checker.check_permission("customer-agent", "send_notification")
        assert result.allowed is True

    def test_revoke_tool_denies_previously_allowed_tool(self, checker: CapabilityChecker) -> None:
        checker.revoke_tool("customer-agent", "search_products")
        result = checker.check_permission("customer-agent", "search_products")
        assert result.allowed is False

    def test_revoke_adds_to_deny_list(self, checker: CapabilityChecker) -> None:
        checker.revoke_tool("customer-agent", "search_products")
        result = checker.check_permission("customer-agent", "search_products")
        # Deny list takes precedence — even if re-granted via allowlist, deny wins.
        assert result.allowed is False

    def test_grant_raises_key_error_for_unknown_agent(self, checker: CapabilityChecker) -> None:
        with pytest.raises(KeyError):
            checker.grant_tool("nonexistent-agent", "some_tool")

    def test_revoke_raises_key_error_for_unknown_agent(self, checker: CapabilityChecker) -> None:
        with pytest.raises(KeyError):
            checker.revoke_tool("nonexistent-agent", "some_tool")


# ---------------------------------------------------------------------------
# Profile registration API
# ---------------------------------------------------------------------------


class TestProfileRegistration:
    def test_register_profile_makes_agent_known(self) -> None:
        checker = CapabilityChecker()
        profile = AgentCapabilityProfile("new-agent", allowed_tools={"tool_a"})
        checker.register_profile(profile)
        result = checker.check_permission("new-agent", "tool_a")
        assert result.allowed is True

    def test_replace_profile_updates_permissions(self) -> None:
        checker = CapabilityChecker()
        checker.register_profile(AgentCapabilityProfile("agent", allowed_tools={"old_tool"}))
        checker.register_profile(AgentCapabilityProfile("agent", allowed_tools={"new_tool"}))

        assert checker.check_permission("agent", "new_tool").allowed is True
        assert checker.check_permission("agent", "old_tool").allowed is False

    def test_empty_profile_denies_all_tools(self) -> None:
        checker = CapabilityChecker()
        checker.register_profile(AgentCapabilityProfile("agent"))
        result = checker.check_permission("agent", "any_tool")
        assert result.allowed is False
