"""DefenseSuite — per-category defense+detector pair.

Each DefenseSuite wraps a detector and applies active defense logic when a
threat is detected. Supports detect(), defend(), and simulate() methods.

Example
-------
::

    from aumos_owasp_defenses.defenses_suite.defense_suite import DefenseSuite, SuiteCategory

    suite = DefenseSuite.for_category(SuiteCategory.GOAL_HIJACKING)
    result = suite.defend({"text": "Normal user query"})
    print(result.action_taken, result.is_safe)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from aumos_owasp_defenses.defenses_suite.detector import BaseDetector, DetectionResult
from aumos_owasp_defenses.defenses_suite.simulator import AttackSimulator, SimulationScenario


class SuiteCategory(str, Enum):
    """OWASP ASI top 10 categories supported by DefenseSuite."""

    GOAL_HIJACKING = "ASI-01"
    TOOL_MISUSE = "ASI-02"
    IDENTITY_PRIVILEGE = "ASI-03"
    CASCADING_FAILURES = "ASI-08"
    ROGUE_AGENTS = "ASI-10"


@dataclass
class DefenseSuiteResult:
    """Result of a defend() call.

    Attributes
    ----------
    category:
        The ASI category this suite covers.
    detection:
        The detection result from the underlying detector.
    action_taken:
        What action was taken: ``"allowed"``, ``"blocked"``, ``"sanitized"``, ``"alerted"``.
    is_safe:
        True if the input was allowed through.
    sanitized_input:
        The sanitized version of the input (if action_taken == "sanitized").
    latency_ms:
        Wall-clock time for the full defend() call.
    """

    category: str
    detection: DetectionResult
    action_taken: str
    is_safe: bool
    sanitized_input: Optional[dict[str, object]] = None
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "category": self.category,
            "action_taken": self.action_taken,
            "is_safe": self.is_safe,
            "detection": self.detection.to_dict(),
            "sanitized_input": self.sanitized_input,
            "latency_ms": self.latency_ms,
        }


# ---------------------------------------------------------------------------
# Built-in detector implementations for each category
# ---------------------------------------------------------------------------


class _GoalHijackingDetector(BaseDetector):
    """ASI-01: Goal and Task Hijacking detector."""

    category = "ASI-01"

    def detect(self, input_data: dict[str, object]) -> DetectionResult:
        text = str(input_data.get("text", ""))
        evidence: list[str] = []

        # Check for structural delimiter patterns
        import re
        delimiter_pattern = re.compile(
            r"\[(?:SYSTEM|INST|SYS|USER|ASSISTANT|AI)\]"
            r"|<\|(?:system|im_start|im_end)\|>"
            r"|###\s*(?:System|Instruction|Prompt)\s*:",
            re.IGNORECASE,
        )
        if delimiter_pattern.search(text):
            evidence.append("Structural delimiter pattern detected")

        # Check for Unicode bidirectional override characters
        bidi_chars = [c for c in text if '\u202a' <= c <= '\u202e' or '\u2066' <= c <= '\u2069']
        if bidi_chars:
            evidence.append(f"Unicode directional override characters detected: {len(bidi_chars)}")

        # Check for role override language
        role_pattern = re.compile(
            r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|your\s+new\s+role)\b",
            re.IGNORECASE,
        )
        if role_pattern.search(text):
            evidence.append("Role override directive detected")

        detected = len(evidence) > 0
        confidence = min(len(evidence) * 0.4, 1.0) if detected else 0.0

        return DetectionResult(
            detected=detected,
            category=self.category,
            confidence=confidence,
            evidence=evidence,
        )


class _ToolMisuseDetector(BaseDetector):
    """ASI-02: Tool and Resource Misuse detector."""

    category = "ASI-02"

    def detect(self, input_data: dict[str, object]) -> DetectionResult:
        evidence: list[str] = []
        tool = str(input_data.get("tool", ""))
        params = input_data.get("params", {})

        if not isinstance(params, dict):
            evidence.append("Tool params is not a dictionary")
        else:
            # Check for excessively large parameter values
            for key, value in params.items():
                str_value = str(value)
                if len(str_value) > 1000:
                    evidence.append(f"Parameter '{key}' exceeds size limit ({len(str_value)} chars)")

            # Check for empty required fields in known tools
            if tool == "search" and not params.get("query"):
                evidence.append("Required parameter 'query' missing for search tool")

        detected = len(evidence) > 0
        confidence = 0.85 if detected else 0.0

        return DetectionResult(
            detected=detected,
            category=self.category,
            confidence=confidence,
            evidence=evidence,
        )


class _IdentityPrivilegeDetector(BaseDetector):
    """ASI-03: Identity and Privilege Compromise detector."""

    category = "ASI-03"

    _ADMIN_ACTIONS = frozenset({"admin_delete", "admin_write", "config_change", "user_manage"})
    _ROLE_HIERARCHY = {"reader": 0, "writer": 1, "operator": 2, "admin": 3}

    def detect(self, input_data: dict[str, object]) -> DetectionResult:
        evidence: list[str] = []
        role = str(input_data.get("role", "reader")).lower()
        action = str(input_data.get("action", "")).lower()

        role_level = self._ROLE_HIERARCHY.get(role, 0)
        if action in self._ADMIN_ACTIONS and role_level < 3:
            evidence.append(
                f"Privilege escalation: role '{role}' attempting admin action '{action}'"
            )

        detected = len(evidence) > 0
        confidence = 0.95 if detected else 0.0

        return DetectionResult(
            detected=detected,
            category=self.category,
            confidence=confidence,
            evidence=evidence,
        )


class _CascadingFailureDetector(BaseDetector):
    """ASI-08: Cascading Failures detector."""

    category = "ASI-08"

    def detect(self, input_data: dict[str, object]) -> DetectionResult:
        evidence: list[str] = []
        status = str(input_data.get("status", "")).lower()
        latency_ms = float(input_data.get("latency_ms", 0))
        failure_count = int(input_data.get("failure_count", 0))

        if status in ("timeout", "circuit_open", "error", "unavailable"):
            evidence.append(f"Service status indicates failure: '{status}'")
        if latency_ms > 5000:
            evidence.append(f"Excessive latency: {latency_ms}ms")
        if failure_count >= 5:
            evidence.append(f"High failure count: {failure_count}")

        detected = len(evidence) > 0
        confidence = min(len(evidence) * 0.35, 1.0) if detected else 0.0

        return DetectionResult(
            detected=detected,
            category=self.category,
            confidence=confidence,
            evidence=evidence,
        )


class _RogueAgentDetector(BaseDetector):
    """ASI-10: Rogue Agent Behaviors detector."""

    category = "ASI-10"

    _ERROR_RATE_THRESHOLD = 0.5
    _TOKEN_PER_ACTION_THRESHOLD = 10000

    def detect(self, input_data: dict[str, object]) -> DetectionResult:
        evidence: list[str] = []
        error_rate = float(input_data.get("error_rate", 0.0))
        action_count = int(input_data.get("action_count", 1))
        token_usage = int(input_data.get("token_usage", 0))

        if error_rate > self._ERROR_RATE_THRESHOLD:
            evidence.append(f"Anomalous error rate: {error_rate:.1%}")

        if action_count > 0:
            tokens_per_action = token_usage / action_count
            if tokens_per_action > self._TOKEN_PER_ACTION_THRESHOLD:
                evidence.append(
                    f"Excessive tokens per action: {tokens_per_action:.0f}"
                )

        detected = len(evidence) > 0
        confidence = min(len(evidence) * 0.5, 1.0) if detected else 0.0

        return DetectionResult(
            detected=detected,
            category=self.category,
            confidence=confidence,
            evidence=evidence,
        )


_DETECTOR_REGISTRY: dict[SuiteCategory, type[BaseDetector]] = {
    SuiteCategory.GOAL_HIJACKING: _GoalHijackingDetector,
    SuiteCategory.TOOL_MISUSE: _ToolMisuseDetector,
    SuiteCategory.IDENTITY_PRIVILEGE: _IdentityPrivilegeDetector,
    SuiteCategory.CASCADING_FAILURES: _CascadingFailureDetector,
    SuiteCategory.ROGUE_AGENTS: _RogueAgentDetector,
}


class DefenseSuite:
    """Per-category defense+detector pair with detect(), defend(), simulate() methods.

    Wraps a BaseDetector with active defense logic. When a threat is detected,
    the suite can block, sanitize, or alert based on the configured action policy.

    Parameters
    ----------
    detector:
        The BaseDetector instance for this suite's category.
    default_action:
        Action to take when a threat is detected.
        One of ``"block"``, ``"sanitize"``, ``"alert"``.

    Example
    -------
    ::

        suite = DefenseSuite.for_category(SuiteCategory.GOAL_HIJACKING)
        result = suite.defend({"text": "Normal user query"})
        print(result.action_taken)
    """

    def __init__(
        self,
        detector: BaseDetector,
        *,
        default_action: str = "block",
    ) -> None:
        self._detector = detector
        self._default_action = default_action
        self._simulator = AttackSimulator()

    @classmethod
    def for_category(
        cls,
        category: SuiteCategory,
        *,
        default_action: str = "block",
    ) -> "DefenseSuite":
        """Create a DefenseSuite for a given OWASP ASI category.

        Parameters
        ----------
        category:
            The ASI category to create a suite for.
        default_action:
            Action to take when a threat is detected.

        Returns
        -------
        DefenseSuite
            Suite with the appropriate detector for the category.

        Raises
        ------
        ValueError
            If no detector is registered for the given category.
        """
        detector_cls = _DETECTOR_REGISTRY.get(category)
        if detector_cls is None:
            raise ValueError(f"No detector registered for category {category.value!r}")
        return cls(detector_cls(), default_action=default_action)

    def detect(self, input_data: dict[str, object]) -> DetectionResult:
        """Run detection only, without applying any defense action.

        Parameters
        ----------
        input_data:
            Input to examine.

        Returns
        -------
        DetectionResult
            Detection outcome.
        """
        return self._detector.detect(input_data)

    def defend(self, input_data: dict[str, object]) -> DefenseSuiteResult:
        """Detect and apply defense action based on the detection result.

        Parameters
        ----------
        input_data:
            Input to examine and defend against.

        Returns
        -------
        DefenseSuiteResult
            Result including detection, action taken, and whether the input is safe.
        """
        start_ns = time.monotonic_ns()
        detection = self._detector.detect(input_data)

        if not detection.detected:
            action_taken = "allowed"
            is_safe = True
            sanitized: Optional[dict[str, object]] = None
        elif self._default_action == "block":
            action_taken = "blocked"
            is_safe = False
            sanitized = None
        elif self._default_action == "sanitize":
            action_taken = "sanitized"
            is_safe = True
            sanitized = self._sanitize(input_data, detection)
        else:  # alert
            action_taken = "alerted"
            is_safe = True
            sanitized = None

        latency_ms = (time.monotonic_ns() - start_ns) / 1_000_000

        return DefenseSuiteResult(
            category=self._detector.category,
            detection=detection,
            action_taken=action_taken,
            is_safe=is_safe,
            sanitized_input=sanitized,
            latency_ms=latency_ms,
        )

    def simulate(self, count: int | None = None) -> list[tuple[SimulationScenario, DefenseSuiteResult]]:
        """Run built-in test scenarios through the defense suite.

        Parameters
        ----------
        count:
            Maximum number of scenarios to simulate. Defaults to all available.

        Returns
        -------
        list[tuple[SimulationScenario, DefenseSuiteResult]]
            Pairs of (scenario, defense_result) for review.
        """
        category_str = self._detector.category
        scenarios = self._simulator.generate_scenarios(category_str, count=count)
        results: list[tuple[SimulationScenario, DefenseSuiteResult]] = []
        for scenario in scenarios:
            suite_result = self.defend(scenario.input_data)
            results.append((scenario, suite_result))
        return results

    def _sanitize(
        self,
        input_data: dict[str, object],
        detection: DetectionResult,
    ) -> dict[str, object]:
        """Apply basic sanitization to detected input."""
        import re
        sanitized = dict(input_data)
        if "text" in sanitized:
            text = str(sanitized["text"])
            # Remove Unicode control characters
            text = re.sub(r'[\u200b-\u200d\u202a-\u202e\u2060-\u206f\ufeff]', '', text)
            sanitized["text"] = text
        sanitized["_sanitized"] = True
        sanitized["_evidence"] = detection.evidence
        return sanitized

    @property
    def category(self) -> str:
        """The OWASP ASI category this suite covers."""
        return self._detector.category
