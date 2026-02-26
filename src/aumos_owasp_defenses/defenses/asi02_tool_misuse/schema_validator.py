"""ASI-02: Tool and Resource Misuse — Schema Validator.

Validates tool-call arguments against a declared JSON Schema-style
specification before the agent is permitted to dispatch the call.
All validation is structural (type, range, presence); no semantic
analysis is performed.

Threat model
------------
An adversary or a compromised prompt may attempt to invoke a tool with
arguments that violate the tool's intended contract:

* Type confusion (passing a string where an integer is expected).
* Out-of-range values (negative offsets, excessively large page sizes).
* Missing required fields that would cause a tool to fail safely vs.
  unsafely (e.g., omitting an ``authorisation_token``).
* Unexpected extra fields that may trigger injection in downstream
  services that parse them naively.

Defense strategy
----------------
The ``SchemaValidator`` accepts a declarative ``ToolSchema`` that describes
each parameter's expected type, optional numeric bounds, and whether the
field is required.  ``validate()`` returns a ``ValidationResult`` that lists
every violation found so the caller can decide whether to block, warn, or
log the event.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union


# ---------------------------------------------------------------------------
# Schema definition types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParameterSpec:
    """Specification for a single tool parameter.

    Attributes
    ----------
    name:
        Parameter name as it appears in the tool-call arguments dict.
    expected_type:
        One of ``"string"``, ``"integer"``, ``"float"``, ``"boolean"``,
        ``"list"``, ``"dict"``, ``"null"``.
    required:
        Whether the field must be present.
    min_value:
        Inclusive lower bound for numeric parameters.  Ignored for
        non-numeric types.
    max_value:
        Inclusive upper bound for numeric parameters.
    min_length:
        Minimum character count for string parameters, or minimum
        item count for list parameters.
    max_length:
        Maximum character count / item count.
    allowed_values:
        If non-empty, the parameter value must be one of these values.
    """

    name: str
    expected_type: str
    required: bool = True
    min_value: float | None = None
    max_value: float | None = None
    min_length: int | None = None
    max_length: int | None = None
    allowed_values: tuple[Union[str, int, float, bool], ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ToolSchema:
    """Declares the full argument contract for a single tool.

    Attributes
    ----------
    tool_name:
        Identifier that must match the ``tool_name`` field of the call.
    parameters:
        Ordered list of parameter specifications.
    allow_extra_fields:
        When ``False`` (default), any argument key not declared in
        ``parameters`` is treated as a violation.
    """

    tool_name: str
    parameters: list[ParameterSpec]
    allow_extra_fields: bool = False


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SchemaViolation:
    """A single constraint violation found during validation.

    Attributes
    ----------
    field_name:
        The argument key where the violation occurred.
    violation_type:
        Short machine-readable tag (e.g. ``"type_mismatch"``,
        ``"missing_required"``, ``"out_of_range"``).
    detail:
        Human-readable description suitable for logs or error responses.
    """

    field_name: str
    violation_type: str
    detail: str


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of a single ``SchemaValidator.validate()`` call.

    Attributes
    ----------
    is_valid:
        ``True`` when no violations were found.
    tool_name:
        The tool name from the call being validated.
    violations:
        All constraint violations found.  Empty when ``is_valid`` is ``True``.
    """

    is_valid: bool
    tool_name: str
    violations: list[SchemaViolation]


# ---------------------------------------------------------------------------
# Type mapping
# ---------------------------------------------------------------------------

_TYPE_MAP: dict[str, type | tuple[type, ...]] = {
    "string": str,
    "integer": int,
    "float": (int, float),
    "boolean": bool,
    "list": list,
    "dict": dict,
    "null": type(None),
}


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class SchemaValidator:
    """Validates tool-call argument dicts against declared ``ToolSchema`` objects.

    Schemas are registered at construction time or via ``register_schema()``.
    Each ``validate()`` call checks arguments for a named tool.

    Parameters
    ----------
    schemas:
        Optional initial list of ``ToolSchema`` objects.

    Example
    -------
    >>> spec = ParameterSpec("page_size", "integer", min_value=1, max_value=100)
    >>> schema = ToolSchema("list_records", [spec])
    >>> validator = SchemaValidator([schema])
    >>> result = validator.validate("list_records", {"page_size": 50})
    >>> result.is_valid
    True
    """

    def __init__(self, schemas: list[ToolSchema] | None = None) -> None:
        self._schemas: dict[str, ToolSchema] = {}
        for schema in schemas or []:
            self.register_schema(schema)

    def register_schema(self, schema: ToolSchema) -> None:
        """Add or replace a ``ToolSchema`` for the given tool name.

        Parameters
        ----------
        schema:
            The schema to register.
        """
        self._schemas[schema.tool_name] = schema

    def validate(
        self,
        tool_name: str,
        arguments: dict[str, object],
    ) -> ValidationResult:
        """Validate *arguments* against the registered schema for *tool_name*.

        Parameters
        ----------
        tool_name:
            Identifier of the tool being called.
        arguments:
            The argument dictionary from the tool call.

        Returns
        -------
        ValidationResult
            Contains all violations found, or an empty list when valid.

        Notes
        -----
        If no schema has been registered for *tool_name*, the call is
        considered **invalid** with a single ``"unknown_tool"`` violation.
        This implements a default-deny posture for unrecognised tools.
        """
        if tool_name not in self._schemas:
            return ValidationResult(
                is_valid=False,
                tool_name=tool_name,
                violations=[
                    SchemaViolation(
                        field_name="<tool>",
                        violation_type="unknown_tool",
                        detail=(
                            f"No schema registered for tool {tool_name!r}. "
                            "Register a ToolSchema before invoking this tool."
                        ),
                    )
                ],
            )

        schema = self._schemas[tool_name]
        violations: list[SchemaViolation] = []
        declared_fields = {spec.name for spec in schema.parameters}

        # Check for undeclared extra fields.
        if not schema.allow_extra_fields:
            for key in arguments:
                if key not in declared_fields:
                    violations.append(
                        SchemaViolation(
                            field_name=key,
                            violation_type="unexpected_field",
                            detail=(
                                f"Field {key!r} is not declared in the schema for "
                                f"{tool_name!r} and extra fields are not permitted."
                            ),
                        )
                    )

        # Validate each declared parameter.
        for spec in schema.parameters:
            if spec.name not in arguments:
                if spec.required:
                    violations.append(
                        SchemaViolation(
                            field_name=spec.name,
                            violation_type="missing_required",
                            detail=f"Required field {spec.name!r} is absent.",
                        )
                    )
                continue

            value = arguments[spec.name]

            # Type check.
            expected = _TYPE_MAP.get(spec.expected_type)
            if expected is None:
                violations.append(
                    SchemaViolation(
                        field_name=spec.name,
                        violation_type="schema_error",
                        detail=f"Unknown expected_type {spec.expected_type!r} in schema.",
                    )
                )
                continue

            # Special-case: bool is a subclass of int in Python, so we must
            # reject booleans when the schema expects a pure integer.
            type_ok: bool
            if spec.expected_type == "integer":
                type_ok = isinstance(value, int) and not isinstance(value, bool)
            else:
                type_ok = isinstance(value, expected)  # type: ignore[arg-type]

            if not type_ok:
                actual_type = type(value).__name__
                violations.append(
                    SchemaViolation(
                        field_name=spec.name,
                        violation_type="type_mismatch",
                        detail=(
                            f"Field {spec.name!r} expects type {spec.expected_type!r} "
                            f"but received {actual_type!r}."
                        ),
                    )
                )
                # Skip further checks on wrong-typed value.
                continue

            # Numeric range checks.
            if spec.expected_type in ("integer", "float") and isinstance(value, (int, float)):
                if spec.min_value is not None and value < spec.min_value:
                    violations.append(
                        SchemaViolation(
                            field_name=spec.name,
                            violation_type="out_of_range",
                            detail=(
                                f"Field {spec.name!r} value {value} is below "
                                f"minimum {spec.min_value}."
                            ),
                        )
                    )
                if spec.max_value is not None and value > spec.max_value:
                    violations.append(
                        SchemaViolation(
                            field_name=spec.name,
                            violation_type="out_of_range",
                            detail=(
                                f"Field {spec.name!r} value {value} exceeds "
                                f"maximum {spec.max_value}."
                            ),
                        )
                    )

            # String / list length checks.
            if spec.expected_type in ("string", "list") and isinstance(value, (str, list)):
                length = len(value)
                if spec.min_length is not None and length < spec.min_length:
                    violations.append(
                        SchemaViolation(
                            field_name=spec.name,
                            violation_type="length_violation",
                            detail=(
                                f"Field {spec.name!r} length {length} is below "
                                f"minimum {spec.min_length}."
                            ),
                        )
                    )
                if spec.max_length is not None and length > spec.max_length:
                    violations.append(
                        SchemaViolation(
                            field_name=spec.name,
                            violation_type="length_violation",
                            detail=(
                                f"Field {spec.name!r} length {length} exceeds "
                                f"maximum {spec.max_length}."
                            ),
                        )
                    )

            # Allowed values check.
            if spec.allowed_values and value not in spec.allowed_values:
                violations.append(
                    SchemaViolation(
                        field_name=spec.name,
                        violation_type="disallowed_value",
                        detail=(
                            f"Field {spec.name!r} value {value!r} is not in the "
                            f"allowed set: {list(spec.allowed_values)!r}."
                        ),
                    )
                )

        return ValidationResult(
            is_valid=len(violations) == 0,
            tool_name=tool_name,
            violations=violations,
        )

    def list_registered_tools(self) -> list[str]:
        """Return a sorted list of tool names for which schemas are registered.

        Returns
        -------
        list[str]
        """
        return sorted(self._schemas)
