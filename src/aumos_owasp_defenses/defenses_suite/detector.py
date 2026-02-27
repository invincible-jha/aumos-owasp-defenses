"""BaseDetector ABC — abstract base for all detection components.

Each defense category has an associated detector that examines input and
returns a DetectionResult indicating whether a threat was detected.

Example
-------
::

    from aumos_owasp_defenses.defenses_suite.detector import BaseDetector, DetectionResult

    class MyDetector(BaseDetector):
        category = "custom"

        def detect(self, input_data: dict) -> DetectionResult:
            suspicious = "danger" in str(input_data)
            return DetectionResult(
                detected=suspicious,
                category=self.category,
                confidence=0.9 if suspicious else 0.0,
                evidence=["Found 'danger' keyword"] if suspicious else [],
            )
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class DetectionResult:
    """Result returned by a detector's detect() call.

    Attributes
    ----------
    detected:
        True if a threat was detected, False otherwise.
    category:
        The OWASP ASI category this result applies to (e.g. ``"ASI-01"``).
    confidence:
        Confidence level for the detection (0.0–1.0).
    evidence:
        Human-readable list of evidence strings explaining the detection.
    metadata:
        Additional structured data from the detection process.
    """

    detected: bool
    category: str
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "detected": self.detected,
            "category": self.category,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


class BaseDetector(ABC):
    """Abstract base class for all detection components.

    Class Attributes
    ----------------
    category:
        The OWASP ASI category this detector covers (e.g. ``"ASI-01"``).

    Subclasses must implement :meth:`detect`.
    """

    category: str = ""

    @abstractmethod
    def detect(self, input_data: dict[str, object]) -> DetectionResult:
        """Examine input and return a DetectionResult.

        Parameters
        ----------
        input_data:
            Arbitrary dictionary describing the input to be analyzed.
            Keys and semantics depend on the specific category.

        Returns
        -------
        DetectionResult
            Detection outcome with confidence and evidence.
        """

    def is_safe(self, input_data: dict[str, object]) -> bool:
        """Convenience method — returns True if no threat detected."""
        return not self.detect(input_data).detected

    def __repr__(self) -> str:
        return f"{type(self).__name__}(category={self.category!r})"
