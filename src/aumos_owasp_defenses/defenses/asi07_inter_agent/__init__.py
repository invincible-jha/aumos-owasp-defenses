"""ASI-07: Inter-Agent Trust Exploitation defenses.

Public surface
--------------
``MessageValidator``
    Validates inter-agent messages against schema and origin-trust policy.
``MessageSchema``
    Structural schema for a message type.
``FieldSpec``
    Specification for a single field within a ``MessageSchema``.
``MessageValidationResult``
    Result of ``MessageValidator.validate_message()``.
``AgentTrustLevel``
    Ordinal trust level enum for message senders.
"""
from __future__ import annotations

from aumos_owasp_defenses.defenses.asi07_inter_agent.message_validator import (
    AgentTrustLevel,
    FieldSpec,
    MessageSchema,
    MessageValidationResult,
    MessageValidator,
)

__all__ = [
    "AgentTrustLevel",
    "FieldSpec",
    "MessageSchema",
    "MessageValidationResult",
    "MessageValidator",
]
