"""ASI-03: Identity and Privilege Compromise — Capability Checker.

Enforces that an agent only invokes tools that fall within its declared
capability set.  Acts as a pre-dispatch gate to prevent privilege escalation
via capability creep or confused-deputy attacks.

Threat model
------------
* An agent may be manipulated into calling tools outside its authorised
  scope (e.g., a customer-service agent calling an admin tool).
* A sub-agent in a multi-agent pipeline may attempt to use capabilities
  granted to its parent rather than those explicitly delegated to it.
* Tool names may be spoofed or aliased to bypass coarse allowlist checks.

Defense strategy
----------------
* Maintain an explicit, immutable capability set per agent identity.
* On every tool-dispatch request, verify the requested tool is within the
  capability set before allowing the call.
* Optionally enforce namespace isolation: tools are prefixed by their
  owning service namespace (e.g., ``"crm.read_contact"``), and agents
  may be restricted to specific namespaces.
* Log every permission decision (allowed and denied) for audit purposes.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Permission result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PermissionResult:
    """Outcome of a ``CapabilityChecker.check_permission()`` call.

    Attributes
    ----------
    allowed:
        ``True`` when the agent is authorised to call the tool.
    agent_id:
        The identity of the agent requesting the permission.
    tool_name:
        The tool being requested.
    reason:
        Human-readable explanation of the decision.
    """

    allowed: bool
    agent_id: str
    tool_name: str
    reason: str


# ---------------------------------------------------------------------------
# Agent capability profile
# ---------------------------------------------------------------------------


@dataclass
class AgentCapabilityProfile:
    """Declares the tools an agent is permitted to call.

    Attributes
    ----------
    agent_id:
        Unique identifier for the agent (e.g. ``"order-agent-v2"``).
    allowed_tools:
        Explicit set of tool names the agent may invoke.  Exact string
        matching is used; no glob or prefix matching by default.
    allowed_namespaces:
        If non-empty, only tools whose name starts with one of these
        namespace prefixes are permitted (in addition to ``allowed_tools``).
        A namespace is the portion of a tool name before the first ``"."``.
    deny_tools:
        Explicit deny list that takes precedence over ``allowed_tools``
        and ``allowed_namespaces``.
    """

    agent_id: str
    allowed_tools: set[str] = field(default_factory=set)
    allowed_namespaces: set[str] = field(default_factory=set)
    deny_tools: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------


class CapabilityChecker:
    """Enforces capability-based access control for agent tool invocations.

    Parameters
    ----------
    profiles:
        Optional initial list of ``AgentCapabilityProfile`` objects.

    Example
    -------
    >>> profile = AgentCapabilityProfile(
    ...     agent_id="assistant",
    ...     allowed_tools={"search_web", "get_weather"},
    ... )
    >>> checker = CapabilityChecker([profile])
    >>> result = checker.check_permission("assistant", "search_web")
    >>> result.allowed
    True
    >>> checker.check_permission("assistant", "delete_database").allowed
    False
    """

    def __init__(self, profiles: list[AgentCapabilityProfile] | None = None) -> None:
        self._profiles: dict[str, AgentCapabilityProfile] = {}
        for profile in profiles or []:
            self.register_profile(profile)

    def register_profile(self, profile: AgentCapabilityProfile) -> None:
        """Register or replace a capability profile for an agent.

        Parameters
        ----------
        profile:
            The profile to register.
        """
        self._profiles[profile.agent_id] = profile
        logger.debug("Registered capability profile for agent %r", profile.agent_id)

    def check_permission(
        self,
        agent_id: str,
        tool_name: str,
    ) -> PermissionResult:
        """Check whether *agent_id* is permitted to call *tool_name*.

        Permission is denied in any of the following cases:

        1. No profile is registered for *agent_id*.
        2. *tool_name* appears in the profile's ``deny_tools`` set.
        3. *tool_name* is not in ``allowed_tools`` and its namespace is
           not in ``allowed_namespaces``.

        Parameters
        ----------
        agent_id:
            The agent requesting the permission check.
        tool_name:
            The tool the agent wants to call.

        Returns
        -------
        PermissionResult
            Contains the decision and a human-readable reason.
        """
        if agent_id not in self._profiles:
            reason = (
                f"No capability profile registered for agent {agent_id!r}. "
                "Register a profile via register_profile() before dispatching tools."
            )
            logger.warning("DENY agent=%r tool=%r reason=%r", agent_id, tool_name, reason)
            return PermissionResult(
                allowed=False,
                agent_id=agent_id,
                tool_name=tool_name,
                reason=reason,
            )

        profile = self._profiles[agent_id]

        # Deny list takes precedence.
        if tool_name in profile.deny_tools:
            reason = (
                f"Tool {tool_name!r} is on the explicit deny list for agent {agent_id!r}."
            )
            logger.warning("DENY agent=%r tool=%r reason=%r", agent_id, tool_name, reason)
            return PermissionResult(
                allowed=False,
                agent_id=agent_id,
                tool_name=tool_name,
                reason=reason,
            )

        # Direct allowlist check.
        if tool_name in profile.allowed_tools:
            reason = f"Tool {tool_name!r} is in the explicit allowlist for agent {agent_id!r}."
            logger.debug("ALLOW agent=%r tool=%r", agent_id, tool_name)
            return PermissionResult(
                allowed=True,
                agent_id=agent_id,
                tool_name=tool_name,
                reason=reason,
            )

        # Namespace check.
        if profile.allowed_namespaces:
            namespace = tool_name.split(".")[0] if "." in tool_name else ""
            if namespace and namespace in profile.allowed_namespaces:
                reason = (
                    f"Tool {tool_name!r} is permitted via namespace {namespace!r} "
                    f"for agent {agent_id!r}."
                )
                logger.debug("ALLOW agent=%r tool=%r via namespace", agent_id, tool_name)
                return PermissionResult(
                    allowed=True,
                    agent_id=agent_id,
                    tool_name=tool_name,
                    reason=reason,
                )

        reason = (
            f"Tool {tool_name!r} is not in the capability set for agent {agent_id!r}. "
            f"Allowed tools: {sorted(profile.allowed_tools)!r}. "
            f"Allowed namespaces: {sorted(profile.allowed_namespaces)!r}."
        )
        logger.warning("DENY agent=%r tool=%r reason=%r", agent_id, tool_name, reason)
        return PermissionResult(
            allowed=False,
            agent_id=agent_id,
            tool_name=tool_name,
            reason=reason,
        )

    def grant_tool(self, agent_id: str, tool_name: str) -> None:
        """Dynamically add *tool_name* to an agent's allowlist.

        Parameters
        ----------
        agent_id:
            The agent to modify.
        tool_name:
            Tool to add.

        Raises
        ------
        KeyError
            If no profile is registered for *agent_id*.
        """
        self._profiles[agent_id].allowed_tools.add(tool_name)

    def revoke_tool(self, agent_id: str, tool_name: str) -> None:
        """Remove *tool_name* from an agent's allowlist.

        Parameters
        ----------
        agent_id:
            The agent to modify.
        tool_name:
            Tool to remove.

        Raises
        ------
        KeyError
            If no profile is registered for *agent_id*.
        """
        self._profiles[agent_id].allowed_tools.discard(tool_name)
        self._profiles[agent_id].deny_tools.add(tool_name)
