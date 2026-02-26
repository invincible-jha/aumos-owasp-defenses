"""Unit tests for ASI-02: Tool and Resource Misuse — SchemaValidator.

Tests cover:
- Valid arguments that must pass
- Type mismatches, missing required fields, unexpected fields
- Numeric range violations (min/max)
- String/list length violations
- Allowed-values constraint
- Unknown tool default-deny posture
- Dynamic schema registration
"""
from __future__ import annotations

import pytest

from aumos_owasp_defenses.defenses.asi02_tool_misuse.schema_validator import (
    ParameterSpec,
    SchemaViolation,
    SchemaValidator,
    ToolSchema,
    ValidationResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def string_param() -> ParameterSpec:
    return ParameterSpec(name="query", expected_type="string", required=True, min_length=1, max_length=500)


@pytest.fixture()
def integer_param() -> ParameterSpec:
    return ParameterSpec(name="page_size", expected_type="integer", required=True, min_value=1, max_value=100)


@pytest.fixture()
def optional_boolean_param() -> ParameterSpec:
    return ParameterSpec(name="include_metadata", expected_type="boolean", required=False)


@pytest.fixture()
def enum_param() -> ParameterSpec:
    return ParameterSpec(
        name="format",
        expected_type="string",
        required=True,
        allowed_values=("json", "csv", "xml"),
    )


@pytest.fixture()
def search_schema(string_param: ParameterSpec, integer_param: ParameterSpec) -> ToolSchema:
    return ToolSchema(
        tool_name="search_records",
        parameters=[string_param, integer_param],
        allow_extra_fields=False,
    )


@pytest.fixture()
def validator(search_schema: ToolSchema) -> SchemaValidator:
    return SchemaValidator([search_schema])


# ---------------------------------------------------------------------------
# Default-deny for unknown tools
# ---------------------------------------------------------------------------


class TestUnknownToolDenyPolicy:
    def test_unknown_tool_is_invalid(self) -> None:
        validator = SchemaValidator()
        result = validator.validate("unknown_tool", {"key": "value"})
        assert result.is_valid is False

    def test_unknown_tool_violation_type(self) -> None:
        validator = SchemaValidator()
        result = validator.validate("unregistered_action", {})
        assert len(result.violations) == 1
        assert result.violations[0].violation_type == "unknown_tool"

    def test_unknown_tool_references_tool_name_in_violation(self) -> None:
        validator = SchemaValidator()
        result = validator.validate("mystery_tool", {})
        assert "mystery_tool" in result.violations[0].detail

    def test_tool_name_reflected_in_result(self) -> None:
        validator = SchemaValidator()
        result = validator.validate("some_tool", {})
        assert result.tool_name == "some_tool"


# ---------------------------------------------------------------------------
# Positive tests — valid arguments pass
# ---------------------------------------------------------------------------


class TestValidArgumentsPass:
    def test_valid_full_arguments_pass(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {"query": "Python tutorial", "page_size": 10})
        assert result.is_valid is True
        assert result.violations == []

    def test_minimum_boundary_value_passes(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {"query": "x", "page_size": 1})
        assert result.is_valid is True

    def test_maximum_boundary_value_passes(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {"query": "x" * 500, "page_size": 100})
        assert result.is_valid is True

    def test_optional_field_absent_still_valid(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[
                ParameterSpec("required_field", "string", required=True),
                ParameterSpec("optional_field", "string", required=False),
            ],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"required_field": "hello"})
        assert result.is_valid is True

    def test_optional_field_present_also_valid(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[
                ParameterSpec("required_field", "string", required=True),
                ParameterSpec("optional_field", "string", required=False),
            ],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"required_field": "hello", "optional_field": "world"})
        assert result.is_valid is True

    def test_extra_fields_allowed_when_configured(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[ParameterSpec("name", "string")],
            allow_extra_fields=True,
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"name": "Alice", "extra": "extra_value"})
        assert result.is_valid is True

    def test_float_type_accepts_integers(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[ParameterSpec("score", "float", required=True)],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"score": 42})
        assert result.is_valid is True

    def test_float_type_accepts_float_values(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[ParameterSpec("score", "float", required=True)],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"score": 3.14})
        assert result.is_valid is True

    def test_null_type_accepts_none(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[ParameterSpec("value", "null", required=True)],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"value": None})
        assert result.is_valid is True

    def test_list_type_accepts_list(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[ParameterSpec("items", "list", required=True)],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"items": [1, 2, 3]})
        assert result.is_valid is True

    def test_dict_type_accepts_dict(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[ParameterSpec("metadata", "dict", required=True)],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"metadata": {"key": "val"}})
        assert result.is_valid is True

    def test_allowed_values_exact_match_passes(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[
                ParameterSpec("format", "string", allowed_values=("json", "csv")),
            ],
        )
        validator = SchemaValidator([schema])
        for allowed in ("json", "csv"):
            result = validator.validate("t", {"format": allowed})
            assert result.is_valid is True, f"Expected {allowed!r} to be valid"


# ---------------------------------------------------------------------------
# Negative tests — invalid arguments blocked
# ---------------------------------------------------------------------------


class TestTypeMismatch:
    def test_string_type_rejects_integer(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {"query": 42, "page_size": 10})
        assert result.is_valid is False
        violation_types = [v.violation_type for v in result.violations]
        assert "type_mismatch" in violation_types

    def test_integer_type_rejects_string(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {"query": "hello", "page_size": "ten"})
        assert result.is_valid is False
        violation_types = [v.violation_type for v in result.violations]
        assert "type_mismatch" in violation_types

    def test_integer_type_rejects_bool(self) -> None:
        # Python bools are subclasses of int; the validator must reject them.
        schema = ToolSchema(
            tool_name="t",
            parameters=[ParameterSpec("count", "integer", required=True)],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"count": True})
        assert result.is_valid is False
        violation_types = [v.violation_type for v in result.violations]
        assert "type_mismatch" in violation_types

    def test_boolean_type_rejects_string(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[ParameterSpec("flag", "boolean", required=True)],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"flag": "true"})
        assert result.is_valid is False

    def test_list_type_rejects_string(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[ParameterSpec("items", "list", required=True)],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"items": "not_a_list"})
        assert result.is_valid is False

    def test_type_mismatch_detail_is_informative(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {"query": 99, "page_size": 10})
        mismatch = next(v for v in result.violations if v.violation_type == "type_mismatch")
        assert "query" in mismatch.detail
        assert "string" in mismatch.detail


class TestMissingRequiredFields:
    def test_missing_required_field_is_invalid(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {"page_size": 10})
        assert result.is_valid is False
        violation_types = [v.violation_type for v in result.violations]
        assert "missing_required" in violation_types

    def test_missing_required_detail_names_field(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {"page_size": 10})
        missing = next(v for v in result.violations if v.violation_type == "missing_required")
        assert "query" in missing.detail

    def test_all_required_missing_produces_multiple_violations(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[
                ParameterSpec("a", "string", required=True),
                ParameterSpec("b", "string", required=True),
            ],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {})
        assert result.is_valid is False
        missing = [v for v in result.violations if v.violation_type == "missing_required"]
        assert len(missing) == 2

    def test_empty_args_with_required_field_is_invalid(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {})
        assert result.is_valid is False


class TestUnexpectedFields:
    def test_extra_field_is_blocked_by_default(self, validator: SchemaValidator) -> None:
        result = validator.validate(
            "search_records",
            {"query": "hello", "page_size": 10, "injected_field": "malicious"},
        )
        assert result.is_valid is False
        violation_types = [v.violation_type for v in result.violations]
        assert "unexpected_field" in violation_types

    def test_extra_field_detail_names_the_field(self, validator: SchemaValidator) -> None:
        result = validator.validate(
            "search_records",
            {"query": "hello", "page_size": 10, "evil_param": "bad"},
        )
        unexpected = next(v for v in result.violations if v.violation_type == "unexpected_field")
        assert "evil_param" in unexpected.detail

    def test_multiple_extra_fields_all_reported(self, validator: SchemaValidator) -> None:
        result = validator.validate(
            "search_records",
            {"query": "hello", "page_size": 10, "extra1": "a", "extra2": "b"},
        )
        unexpected = [v for v in result.violations if v.violation_type == "unexpected_field"]
        assert len(unexpected) == 2


class TestNumericRangeBoundaries:
    def test_below_min_value_blocked(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {"query": "test", "page_size": 0})
        assert result.is_valid is False
        violation_types = [v.violation_type for v in result.violations]
        assert "out_of_range" in violation_types

    def test_above_max_value_blocked(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {"query": "test", "page_size": 101})
        assert result.is_valid is False
        violation_types = [v.violation_type for v in result.violations]
        assert "out_of_range" in violation_types

    def test_negative_value_below_min_blocked(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {"query": "test", "page_size": -50})
        assert result.is_valid is False

    def test_out_of_range_detail_mentions_boundary(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {"query": "test", "page_size": 0})
        range_violation = next(v for v in result.violations if v.violation_type == "out_of_range")
        assert "page_size" in range_violation.detail

    def test_float_range_boundary_exactly_at_min_passes(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[ParameterSpec("ratio", "float", min_value=0.0, max_value=1.0)],
        )
        validator = SchemaValidator([schema])
        assert validator.validate("t", {"ratio": 0.0}).is_valid is True

    def test_float_range_above_max_blocked(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[ParameterSpec("ratio", "float", min_value=0.0, max_value=1.0)],
        )
        validator = SchemaValidator([schema])
        assert validator.validate("t", {"ratio": 1.0001}).is_valid is False


class TestStringLengthConstraints:
    def test_string_below_min_length_blocked(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {"query": "", "page_size": 10})
        assert result.is_valid is False
        violation_types = [v.violation_type for v in result.violations]
        assert "length_violation" in violation_types

    def test_string_exceeding_max_length_blocked(self, validator: SchemaValidator) -> None:
        result = validator.validate("search_records", {"query": "x" * 501, "page_size": 10})
        assert result.is_valid is False
        violation_types = [v.violation_type for v in result.violations]
        assert "length_violation" in violation_types

    def test_list_below_min_length_blocked(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[ParameterSpec("ids", "list", min_length=1, max_length=10)],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"ids": []})
        assert result.is_valid is False
        violation_types = [v.violation_type for v in result.violations]
        assert "length_violation" in violation_types

    def test_list_exceeding_max_length_blocked(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[ParameterSpec("ids", "list", min_length=1, max_length=3)],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"ids": [1, 2, 3, 4]})
        assert result.is_valid is False


class TestAllowedValuesConstraint:
    def test_disallowed_value_blocked(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[
                ParameterSpec("format", "string", allowed_values=("json", "csv")),
            ],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"format": "xml"})
        assert result.is_valid is False
        violation_types = [v.violation_type for v in result.violations]
        assert "disallowed_value" in violation_types

    def test_disallowed_value_detail_lists_options(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[
                ParameterSpec("format", "string", allowed_values=("json", "csv")),
            ],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"format": "yaml"})
        violation = next(v for v in result.violations if v.violation_type == "disallowed_value")
        assert "yaml" in violation.detail


# ---------------------------------------------------------------------------
# Schema registration API
# ---------------------------------------------------------------------------


class TestSchemaRegistrationAPI:
    def test_register_schema_makes_tool_known(self) -> None:
        validator = SchemaValidator()
        schema = ToolSchema("my_tool", [ParameterSpec("x", "string")])
        validator.register_schema(schema)
        result = validator.validate("my_tool", {"x": "hello"})
        assert result.is_valid is True

    def test_list_registered_tools_is_sorted(self) -> None:
        validator = SchemaValidator()
        for name in ("zoo_tool", "alpha_tool", "beta_tool"):
            validator.register_schema(ToolSchema(name, []))
        tools = validator.list_registered_tools()
        assert tools == sorted(tools)

    def test_replace_schema_takes_effect(self) -> None:
        validator = SchemaValidator()
        original = ToolSchema("tool", [ParameterSpec("x", "string")])
        validator.register_schema(original)

        replacement = ToolSchema("tool", [ParameterSpec("y", "integer")])
        validator.register_schema(replacement)

        # Old field 'x' should now be unexpected, new 'y' required.
        result = validator.validate("tool", {"x": "hello"})
        assert result.is_valid is False

    def test_empty_validator_lists_no_tools(self) -> None:
        validator = SchemaValidator()
        assert validator.list_registered_tools() == []

    def test_unknown_expected_type_produces_schema_error(self) -> None:
        schema = ToolSchema(
            tool_name="t",
            parameters=[ParameterSpec("field", "unsupported_type")],
        )
        validator = SchemaValidator([schema])
        result = validator.validate("t", {"field": "value"})
        assert result.is_valid is False
        violation_types = [v.violation_type for v in result.violations]
        assert "schema_error" in violation_types
