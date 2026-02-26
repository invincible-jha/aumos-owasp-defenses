"""ASI-07: Inter-Agent Trust Exploitation — Message Validator.

Validates messages exchanged between agents in a multi-agent pipeline
against a declared structural schema and origin-trust policy.

Threat model
------------
* A compromised or rogue sub-agent sends a crafted message to a peer or
  orchestrator agent, attempting to inject instructions, forge identity,
  or escalate privilege.
* Messages from external systems are relayed through an intermediate agent
  without sanitisation, causing the receiving agent to treat external data
  as trusted agent communication.
* Replay attacks: a previously valid message is re-submitted to trigger
  an operation a second time.

Defense strategy
----------------
* Require all inter-agent messages to carry a declared ``sender_id``,
  ``message_type``, and ``correlation_id``.
* Validate the message structure against a per-message-type schema.
* Enforce an origin-trust policy: only messages from registered senders
  with sufficient trust level are accepted.
* Optionally enforce replay protection via a seen-correlation-id cache
  with configurable TTL.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import IntEnum

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Agent trust levels
# ---------------------------------------------------------------------------


class AgentTrustLevel(IntEnum):
    """Trust level assigned to a message sender.

    * ``UNTRUSTED``: sender is not registered or its identity could not
      be verified.
    * ``LOW``: sender is a registered agent in a restricted role.
    * ``MEDIUM``: sender is a peer agent with standard permissions.
    * ``HIGH``: sender is a trusted orchestrator or supervisor agent.
    * ``SYSTEM``: sender is the platform itself (reserved for internal use).
    """

    UNTRUSTED = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    SYSTEM = 4


# ---------------------------------------------------------------------------
# Message schema
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldSpec:
    """Specification for a single field in a message schema.

    Attributes
    ----------
    name:
        Field name in the message dict.
    expected_type:
        Python type name string: ``"str"``, ``"int"``, ``"float"``,
        ``"bool"``, ``"list"``, ``"dict"``.
    required:
        Whether the field must be present.
    max_length:
        Maximum string or list length (ignored for non-applicable types).
    """

    name: str
    expected_type: str
    required: bool = True
    max_length: int | None = None


@dataclass(frozen=True)
class MessageSchema:
    """Structural schema for a message type.

    Attributes
    ----------
    message_type:
        The message type string this schema applies to.
    fields:
        List of field specifications.
    required_trust:
        Minimum sender trust level to accept this message type.
    allow_extra_fields:
        Whether unrecognised fields are permitted.
    """

    message_type: str
    fields: list[FieldSpec]
    required_trust: AgentTrustLevel = AgentTrustLevel.MEDIUM
    allow_extra_fields: bool = False


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MessageValidationResult:
    """Outcome of ``MessageValidator.validate_message()``.

    Attributes
    ----------
    valid:
        ``True`` when all checks pass.
    sender_id:
        Sender declared in the message.
    message_type:
        Message type declared in the message.
    violations:
        Human-readable descriptions of all violations found.
    is_replay:
        ``True`` when the correlation_id has been seen before.
    """

    valid: bool
    sender_id: str
    message_type: str
    violations: list[str]
    is_replay: bool


# ---------------------------------------------------------------------------
# Type map
# ---------------------------------------------------------------------------

_PYTHON_TYPE_MAP: dict[str, type | tuple[type, ...]] = {
    "str": str,
    "int": int,
    "float": (int, float),
    "bool": bool,
    "list": list,
    "dict": dict,
}

# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class MessageValidator:
    """Validates inter-agent messages against schema and origin-trust policy.

    Parameters
    ----------
    replay_protection_ttl_seconds:
        How long (in seconds) a correlation_id is remembered for replay
        protection.  Set to ``0`` to disable replay protection.  Default
        is 300 seconds (5 minutes).

    Example
    -------
    >>> schema = MessageSchema(
    ...     message_type="task_request",
    ...     fields=[FieldSpec("task_id", "str"), FieldSpec("payload", "dict")],
    ...     required_trust=AgentTrustLevel.MEDIUM,
    ... )
    >>> validator = MessageValidator()
    >>> validator.register_schema(schema)
    >>> validator.register_sender("orchestrator", AgentTrustLevel.HIGH)
    >>> msg = {
    ...     "sender_id": "orchestrator",
    ...     "message_type": "task_request",
    ...     "correlation_id": "abc-123",
    ...     "task_id": "t1",
    ...     "payload": {},
    ... }
    >>> validator.validate_message(msg).valid
    True
    """

    _ENVELOPE_FIELDS: frozenset[str] = frozenset(
        {"sender_id", "message_type", "correlation_id"}
    )

    def __init__(self, replay_protection_ttl_seconds: float = 300.0) -> None:
        self._schemas: dict[str, MessageSchema] = {}
        self._sender_trust: dict[str, AgentTrustLevel] = {}
        self._ttl = replay_protection_ttl_seconds
        # correlation_id -> expiry timestamp (monotonic)
        self._seen_correlations: dict[str, float] = {}

    def register_schema(self, schema: MessageSchema) -> None:
        """Register a message schema.

        Parameters
        ----------
        schema:
            Schema to register.
        """
        self._schemas[schema.message_type] = schema

    def register_sender(self, sender_id: str, trust_level: AgentTrustLevel) -> None:
        """Register a known sender with its trust level.

        Parameters
        ----------
        sender_id:
            Agent identifier.
        trust_level:
            Trust level to assign.
        """
        self._sender_trust[sender_id] = trust_level

    def validate_message(self, message: dict[str, object]) -> MessageValidationResult:
        """Validate an inter-agent *message* dict.

        Parameters
        ----------
        message:
            The message to validate.  Must be a plain ``dict`` with at
            least ``sender_id``, ``message_type``, and ``correlation_id``
            envelope fields.

        Returns
        -------
        MessageValidationResult
        """
        violations: list[str] = []
        is_replay = False

        # --- Envelope field presence ---
        sender_id = str(message.get("sender_id", ""))
        message_type = str(message.get("message_type", ""))
        correlation_id = str(message.get("correlation_id", ""))

        for envelope_field in ("sender_id", "message_type", "correlation_id"):
            if envelope_field not in message or not str(message[envelope_field]).strip():
                violations.append(
                    f"Envelope field {envelope_field!r} is missing or empty."
                )

        # --- Replay protection ---
        if self._ttl > 0 and correlation_id:
            self._evict_expired()
            if correlation_id in self._seen_correlations:
                is_replay = True
                violations.append(
                    f"Replay detected: correlation_id {correlation_id!r} has been "
                    "seen before.  This message may be a replay attack."
                )
            else:
                expiry = time.monotonic() + self._ttl
                self._seen_correlations[correlation_id] = expiry

        # --- Sender trust ---
        sender_trust = self._sender_trust.get(sender_id, AgentTrustLevel.UNTRUSTED)
        if sender_id and sender_id not in self._sender_trust:
            violations.append(
                f"Sender {sender_id!r} is not registered.  Register senders via "
                "register_sender() to assign a trust level."
            )

        # --- Schema validation ---
        if message_type not in self._schemas:
            violations.append(
                f"No schema registered for message_type={message_type!r}. "
                "Register a MessageSchema via register_schema()."
            )
        else:
            schema = self._schemas[message_type]

            # Trust level check.
            if sender_trust < schema.required_trust:
                violations.append(
                    f"Sender {sender_id!r} trust level {sender_trust.name} is below "
                    f"required {schema.required_trust.name} for message type "
                    f"{message_type!r}."
                )

            # Check for unexpected fields.
            declared = {f.name for f in schema.fields} | self._ENVELOPE_FIELDS
            if not schema.allow_extra_fields:
                for key in message:
                    if key not in declared:
                        violations.append(
                            f"Unexpected field {key!r} in message of type "
                            f"{message_type!r}."
                        )

            # Validate declared fields.
            for spec in schema.fields:
                if spec.name not in message:
                    if spec.required:
                        violations.append(
                            f"Required field {spec.name!r} is missing from "
                            f"message type {message_type!r}."
                        )
                    continue

                value = message[spec.name]
                expected = _PYTHON_TYPE_MAP.get(spec.expected_type)
                if expected is None:
                    violations.append(
                        f"Schema error: unknown expected_type {spec.expected_type!r} "
                        f"for field {spec.name!r}."
                    )
                    continue

                if spec.expected_type == "int":
                    type_ok = isinstance(value, int) and not isinstance(value, bool)
                else:
                    type_ok = isinstance(value, expected)  # type: ignore[arg-type]

                if not type_ok:
                    violations.append(
                        f"Field {spec.name!r} expected type {spec.expected_type!r} "
                        f"but received {type(value).__name__!r}."
                    )
                    continue

                if spec.max_length is not None and isinstance(value, (str, list)):
                    if len(value) > spec.max_length:
                        violations.append(
                            f"Field {spec.name!r} length {len(value)} exceeds "
                            f"max_length {spec.max_length}."
                        )

        return MessageValidationResult(
            valid=len(violations) == 0,
            sender_id=sender_id,
            message_type=message_type,
            violations=violations,
            is_replay=is_replay,
        )

    def _evict_expired(self) -> None:
        """Remove expired correlation IDs from the seen-set."""
        now = time.monotonic()
        expired = [k for k, expiry in self._seen_correlations.items() if expiry <= now]
        for key in expired:
            del self._seen_correlations[key]
