"""Tests for ASI-07 MessageValidator."""
from __future__ import annotations

import pytest

from aumos_owasp_defenses.defenses.asi07_inter_agent.message_validator import (
    AgentTrustLevel,
    FieldSpec,
    MessageSchema,
    MessageValidationResult,
    MessageValidator,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def task_schema() -> MessageSchema:
    return MessageSchema(
        message_type="task_request",
        fields=[
            FieldSpec("task_id", "str"),
            FieldSpec("payload", "dict"),
        ],
        required_trust=AgentTrustLevel.MEDIUM,
    )


@pytest.fixture()
def validator(task_schema: MessageSchema) -> MessageValidator:
    v = MessageValidator(replay_protection_ttl_seconds=300.0)
    v.register_schema(task_schema)
    v.register_sender("orchestrator", AgentTrustLevel.HIGH)
    v.register_sender("worker", AgentTrustLevel.MEDIUM)
    v.register_sender("restricted-agent", AgentTrustLevel.LOW)
    return v


@pytest.fixture()
def valid_message() -> dict[str, object]:
    return {
        "sender_id": "orchestrator",
        "message_type": "task_request",
        "correlation_id": "corr-001",
        "task_id": "task-abc",
        "payload": {},
    }


# ---------------------------------------------------------------------------
# AgentTrustLevel
# ---------------------------------------------------------------------------


class TestAgentTrustLevel:
    def test_ordering(self) -> None:
        assert AgentTrustLevel.UNTRUSTED < AgentTrustLevel.LOW
        assert AgentTrustLevel.LOW < AgentTrustLevel.MEDIUM
        assert AgentTrustLevel.MEDIUM < AgentTrustLevel.HIGH
        assert AgentTrustLevel.HIGH < AgentTrustLevel.SYSTEM


# ---------------------------------------------------------------------------
# MessageValidator — valid messages
# ---------------------------------------------------------------------------


class TestValidMessage:
    def test_valid_message_passes(
        self, validator: MessageValidator, valid_message: dict[str, object]
    ) -> None:
        result = validator.validate_message(valid_message)
        assert result.valid is True
        assert result.violations == []
        assert result.is_replay is False

    def test_result_has_sender_and_type(
        self, validator: MessageValidator, valid_message: dict[str, object]
    ) -> None:
        result = validator.validate_message(valid_message)
        assert result.sender_id == "orchestrator"
        assert result.message_type == "task_request"


# ---------------------------------------------------------------------------
# MessageValidator — envelope validation
# ---------------------------------------------------------------------------


class TestEnvelopeValidation:
    def test_missing_sender_id(self, validator: MessageValidator) -> None:
        msg: dict[str, object] = {
            "message_type": "task_request",
            "correlation_id": "c1",
            "task_id": "t1",
            "payload": {},
        }
        result = validator.validate_message(msg)
        assert result.valid is False
        assert any("sender_id" in v for v in result.violations)

    def test_missing_message_type(self, validator: MessageValidator) -> None:
        msg: dict[str, object] = {
            "sender_id": "orchestrator",
            "correlation_id": "c1",
            "task_id": "t1",
            "payload": {},
        }
        result = validator.validate_message(msg)
        assert result.valid is False

    def test_missing_correlation_id(self, validator: MessageValidator) -> None:
        msg: dict[str, object] = {
            "sender_id": "orchestrator",
            "message_type": "task_request",
            "task_id": "t1",
            "payload": {},
        }
        result = validator.validate_message(msg)
        assert result.valid is False
        assert any("correlation_id" in v for v in result.violations)

    def test_empty_string_envelope_field(self, validator: MessageValidator) -> None:
        msg: dict[str, object] = {
            "sender_id": "",
            "message_type": "task_request",
            "correlation_id": "c1",
            "task_id": "t1",
            "payload": {},
        }
        result = validator.validate_message(msg)
        assert result.valid is False


# ---------------------------------------------------------------------------
# MessageValidator — sender trust
# ---------------------------------------------------------------------------


class TestSenderTrust:
    def test_unregistered_sender_fails(
        self, validator: MessageValidator
    ) -> None:
        msg: dict[str, object] = {
            "sender_id": "unknown-agent",
            "message_type": "task_request",
            "correlation_id": "c1",
            "task_id": "t1",
            "payload": {},
        }
        result = validator.validate_message(msg)
        assert result.valid is False
        assert any("not registered" in v for v in result.violations)

    def test_insufficient_trust_fails(self, validator: MessageValidator) -> None:
        msg: dict[str, object] = {
            "sender_id": "restricted-agent",  # LOW trust, needs MEDIUM
            "message_type": "task_request",
            "correlation_id": "c1",
            "task_id": "t1",
            "payload": {},
        }
        result = validator.validate_message(msg)
        assert result.valid is False
        assert any("trust level" in v.lower() for v in result.violations)

    def test_sufficient_trust_passes(
        self, validator: MessageValidator, valid_message: dict[str, object]
    ) -> None:
        result = validator.validate_message(valid_message)
        assert result.valid is True


# ---------------------------------------------------------------------------
# MessageValidator — schema validation
# ---------------------------------------------------------------------------


class TestSchemaValidation:
    def test_missing_required_field(self, validator: MessageValidator) -> None:
        msg: dict[str, object] = {
            "sender_id": "orchestrator",
            "message_type": "task_request",
            "correlation_id": "c1",
            "payload": {},  # task_id missing
        }
        result = validator.validate_message(msg)
        assert result.valid is False
        assert any("task_id" in v for v in result.violations)

    def test_wrong_field_type(self, validator: MessageValidator) -> None:
        msg: dict[str, object] = {
            "sender_id": "orchestrator",
            "message_type": "task_request",
            "correlation_id": "c1",
            "task_id": 123,  # Should be str
            "payload": {},
        }
        result = validator.validate_message(msg)
        assert result.valid is False
        assert any("type" in v.lower() for v in result.violations)

    def test_extra_field_not_allowed(self, validator: MessageValidator) -> None:
        msg: dict[str, object] = {
            "sender_id": "orchestrator",
            "message_type": "task_request",
            "correlation_id": "c1",
            "task_id": "t1",
            "payload": {},
            "extra_sneaky_field": "injected",
        }
        result = validator.validate_message(msg)
        assert result.valid is False
        assert any("extra_sneaky_field" in v or "unexpected" in v.lower() for v in result.violations)

    def test_extra_field_allowed_when_configured(self) -> None:
        schema = MessageSchema(
            message_type="flexible",
            fields=[FieldSpec("data", "str")],
            allow_extra_fields=True,
        )
        v = MessageValidator()
        v.register_schema(schema)
        v.register_sender("agent", AgentTrustLevel.HIGH)
        msg: dict[str, object] = {
            "sender_id": "agent",
            "message_type": "flexible",
            "correlation_id": "c1",
            "data": "hello",
            "unexpected": "ok",
        }
        result = v.validate_message(msg)
        assert result.valid is True

    def test_no_schema_for_message_type(self, validator: MessageValidator) -> None:
        msg: dict[str, object] = {
            "sender_id": "orchestrator",
            "message_type": "unknown_type",
            "correlation_id": "c1",
        }
        result = validator.validate_message(msg)
        assert result.valid is False
        assert any("no schema" in v.lower() for v in result.violations)

    def test_max_length_violation_string(self, validator: MessageValidator) -> None:
        schema = MessageSchema(
            message_type="limited",
            fields=[FieldSpec("name", "str", max_length=5)],
        )
        validator.register_schema(schema)
        msg: dict[str, object] = {
            "sender_id": "orchestrator",
            "message_type": "limited",
            "correlation_id": "c1",
            "name": "this is too long",
        }
        result = validator.validate_message(msg)
        assert result.valid is False
        assert any("max_length" in v for v in result.violations)

    def test_optional_field_absent_is_ok(self) -> None:
        schema = MessageSchema(
            message_type="optional_test",
            fields=[
                FieldSpec("required_field", "str", required=True),
                FieldSpec("optional_field", "str", required=False),
            ],
        )
        v = MessageValidator()
        v.register_schema(schema)
        v.register_sender("agent", AgentTrustLevel.HIGH)
        msg: dict[str, object] = {
            "sender_id": "agent",
            "message_type": "optional_test",
            "correlation_id": "c1",
            "required_field": "present",
        }
        result = v.validate_message(msg)
        assert result.valid is True

    def test_bool_not_accepted_as_int(self, validator: MessageValidator) -> None:
        schema = MessageSchema(
            message_type="int_test",
            fields=[FieldSpec("count", "int")],
        )
        validator.register_schema(schema)
        msg: dict[str, object] = {
            "sender_id": "orchestrator",
            "message_type": "int_test",
            "correlation_id": "c1",
            "count": True,  # bool should not satisfy int spec
        }
        result = validator.validate_message(msg)
        assert result.valid is False


# ---------------------------------------------------------------------------
# MessageValidator — replay protection
# ---------------------------------------------------------------------------


class TestReplayProtection:
    def test_replay_detected_on_second_use(
        self, validator: MessageValidator, valid_message: dict[str, object]
    ) -> None:
        validator.validate_message(valid_message)
        result2 = validator.validate_message(valid_message)
        assert result2.is_replay is True
        assert result2.valid is False

    def test_different_correlation_id_not_replay(
        self, validator: MessageValidator, valid_message: dict[str, object]
    ) -> None:
        validator.validate_message(valid_message)
        msg2 = dict(valid_message)
        msg2["correlation_id"] = "different-corr-id"
        result = validator.validate_message(msg2)
        assert result.is_replay is False

    def test_replay_protection_disabled_with_zero_ttl(self) -> None:
        v = MessageValidator(replay_protection_ttl_seconds=0)
        schema = MessageSchema(
            message_type="t",
            fields=[FieldSpec("x", "str")],
            required_trust=AgentTrustLevel.LOW,
        )
        v.register_schema(schema)
        v.register_sender("agent", AgentTrustLevel.HIGH)
        msg: dict[str, object] = {
            "sender_id": "agent",
            "message_type": "t",
            "correlation_id": "same-corr",
            "x": "hello",
        }
        v.validate_message(msg)
        result2 = v.validate_message(msg)
        assert result2.is_replay is False
