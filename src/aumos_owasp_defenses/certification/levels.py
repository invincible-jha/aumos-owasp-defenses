"""Certification level definitions for OWASP ASI compliance.

Three certification levels are defined, each with progressively stricter
requirements across the ten OWASP Agentic Security Initiative categories.

Levels
------
ASI-Basic:
    At least 7 of 10 categories pass at WARN level.  Simple configuration
    checks are sufficient; one or more categories may have open findings.

ASI-Standard:
    All 10 categories pass at WARN level, and at least 7 of 10 pass at
    STRICT level.  Thorough controls must be in place for most categories.

ASI-Advanced:
    All 10 categories pass at STRICT level.  Every comprehensive check
    must pass with no material gaps.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CertificationLevel(str, Enum):
    """Ordered enumeration of OWASP ASI compliance certification levels.

    The string value is used in human-readable output and as the badge
    label text.  Levels are ordered from no certification (NONE) through
    to the most rigorous level (ADVANCED).
    """

    NONE = "none"
    BASIC = "asi-basic"
    STANDARD = "asi-standard"
    ADVANCED = "asi-advanced"

    def display_name(self) -> str:
        """Return a title-cased label suitable for badge and report display."""
        labels: dict[str, str] = {
            "none": "No Certification",
            "asi-basic": "ASI Basic",
            "asi-standard": "ASI Standard",
            "asi-advanced": "ASI Advanced",
        }
        return labels[self.value]

    def badge_color(self) -> str:
        """Return the hex colour used for this level's SVG badge."""
        colors: dict[str, str] = {
            "none": "#e05d44",       # red
            "asi-basic": "#dfb317",  # yellow
            "asi-standard": "#007ec6",  # blue
            "asi-advanced": "#44cc11",  # green
        }
        return colors[self.value]


@dataclass(frozen=True)
class LevelThresholds:
    """Numeric pass thresholds required to attain a certification level.

    Attributes
    ----------
    warn_required:
        Minimum number of categories that must pass at WARN level.
    strict_required:
        Minimum number of categories that must pass at STRICT level.
    total_categories:
        Total number of OWASP ASI categories assessed (always 10).
    """

    warn_required: int
    strict_required: int
    total_categories: int = 10


#: Threshold definitions keyed by :class:`CertificationLevel`.
LEVEL_THRESHOLDS: dict[CertificationLevel, LevelThresholds] = {
    CertificationLevel.BASIC: LevelThresholds(
        warn_required=7,
        strict_required=0,
    ),
    CertificationLevel.STANDARD: LevelThresholds(
        warn_required=10,
        strict_required=7,
    ),
    CertificationLevel.ADVANCED: LevelThresholds(
        warn_required=10,
        strict_required=10,
    ),
}


def determine_level(warn_passed: int, strict_passed: int) -> CertificationLevel:
    """Determine the highest :class:`CertificationLevel` earned.

    Evaluates thresholds from most rigorous to least, returning the first
    level whose requirements are fully satisfied.

    Parameters
    ----------
    warn_passed:
        Count of categories that passed at WARN level (simple checks).
    strict_passed:
        Count of categories that passed at STRICT level (thorough checks).

    Returns
    -------
    CertificationLevel
        The highest level attained, or :attr:`CertificationLevel.NONE`
        when no level's requirements are met.

    Examples
    --------
    >>> determine_level(10, 10)
    <CertificationLevel.ADVANCED: 'asi-advanced'>
    >>> determine_level(10, 7)
    <CertificationLevel.STANDARD: 'asi-standard'>
    >>> determine_level(7, 0)
    <CertificationLevel.BASIC: 'asi-basic'>
    >>> determine_level(6, 0)
    <CertificationLevel.NONE: 'none'>
    """
    for level in (
        CertificationLevel.ADVANCED,
        CertificationLevel.STANDARD,
        CertificationLevel.BASIC,
    ):
        thresholds = LEVEL_THRESHOLDS[level]
        if (
            warn_passed >= thresholds.warn_required
            and strict_passed >= thresholds.strict_required
        ):
            return level
    return CertificationLevel.NONE
