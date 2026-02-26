"""ASI-03: Identity and Privilege Compromise defenses.

Public surface
--------------
``CapabilityChecker``
    Enforces capability-based access control for agent tool invocations.
``AgentCapabilityProfile``
    Declares the tools an agent is permitted to call.
``PermissionResult``
    Result object returned by ``CapabilityChecker.check_permission()``.
"""
from __future__ import annotations

from aumos_owasp_defenses.defenses.asi03_identity_privilege.capability_checker import (
    AgentCapabilityProfile,
    CapabilityChecker,
    PermissionResult,
)

__all__ = [
    "AgentCapabilityProfile",
    "CapabilityChecker",
    "PermissionResult",
]
