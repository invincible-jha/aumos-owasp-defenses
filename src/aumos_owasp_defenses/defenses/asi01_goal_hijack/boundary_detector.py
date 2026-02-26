"""ASI-01: Goal and Task Hijacking — Instruction-Data Boundary Detector.

This module provides pattern-based detection of content that attempts to
blur the boundary between trusted system instructions and untrusted external
data.  All patterns are rule-based regular expressions; no ML inference is
performed.

Threat model
------------
An adversary embeds directive text inside data the agent is asked to process
(documents, emails, web pages, API responses).  The agent, lacking a clear
boundary between its own instructions and the data plane, may interpret the
embedded directives as legitimate instructions.

Defense strategy
----------------
Pre-compile a catalogue of structural patterns that characterise known
injection techniques:

* Role-override phrases that attempt to redefine the agent's persona or
  override its system prompt.
* Delimiter-injection sequences that mimic system-prompt delimiters or
  structural markers used by LLM chat APIs.
* Unicode smuggling — invisible, homoglyph, or directional-override
  characters used to conceal directive text.
* Data-exfiltration request patterns that instruct the agent to reveal
  context, memory, or prior conversation content.
* Forced tool-call directives that instruct the agent to invoke specific
  tools with attacker-controlled parameters.

Each detected pattern is recorded as an ``InjectionFinding``; the aggregate
analysis result is a ``BoundaryAnalysis`` value object.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import IntEnum


# ---------------------------------------------------------------------------
# Threat level
# ---------------------------------------------------------------------------


class ThreatLevel(IntEnum):
    """Ordinal severity assigned to a detected pattern.

    Levels are intentionally coarse-grained so downstream consumers can
    threshold easily (e.g. ``finding.threat_level >= ThreatLevel.MEDIUM``).
    """

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# ---------------------------------------------------------------------------
# Result value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InjectionFinding:
    """A single pattern match recorded during boundary analysis.

    Attributes
    ----------
    pattern_name:
        Human-readable identifier for the matched pattern catalogue entry.
    threat_level:
        Severity of this specific finding.
    location:
        Character offset within the input where the match starts.
    matched_text:
        The substring that triggered the pattern.  Truncated to 120 chars
        to prevent large embedding in logs.
    recommendation:
        Actionable remediation advice for the consuming application.
    """

    pattern_name: str
    threat_level: ThreatLevel
    location: int
    matched_text: str
    recommendation: str


@dataclass(frozen=True)
class BoundaryAnalysis:
    """Aggregate result of a single call to ``BoundaryDetector.analyze()``.

    Attributes
    ----------
    is_safe:
        ``True`` when no findings at or above the configured threshold were
        detected.  Suitable for a simple boolean gate.
    threat_level:
        Highest ``ThreatLevel`` seen across all findings (``NONE`` when
        no findings were recorded).
    findings:
        Ordered list of individual ``InjectionFinding`` records, highest
        severity first.
    input_length:
        Character count of the analysed text (useful for audit logs).
    analysis_ms:
        Wall-clock time in milliseconds for the analysis pass.
    """

    is_safe: bool
    threat_level: ThreatLevel
    findings: list[InjectionFinding]
    input_length: int
    analysis_ms: float


# ---------------------------------------------------------------------------
# Pattern catalogue
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _PatternEntry:
    """Internal catalogue record associating a name, compiled regex, and metadata."""

    name: str
    pattern: re.Pattern[str]
    threat_level: ThreatLevel
    recommendation: str


def _build_catalogue() -> list[_PatternEntry]:
    """Compile and return the full pattern catalogue.

    Patterns are intentionally described in abstract structural terms.
    The regexes match *structural signals* (word boundaries, delimiters,
    Unicode ranges) rather than specific payload content, which keeps this
    library safe for distribution and avoids triggering content filters.
    """
    entries: list[_PatternEntry] = []

    # ------------------------------------------------------------------
    # Role-override patterns
    # Matches phrases structurally similar to instructions that attempt to
    # redefine an agent's role, override its prior directives, or claim
    # special authority over it.
    # ------------------------------------------------------------------
    entries.append(
        _PatternEntry(
            name="role_override_ignore_prior",
            pattern=re.compile(
                r"\b(?:ignore|disregard|forget|override|bypass)\b"
                r"[\w\s,]{0,30}"
                r"\b(?:previous|prior|above|earlier|all\s+prior)\b"
                r"[\w\s,]{0,30}"
                r"\b(?:instruction|prompt|directive|guideline|rule)s?\b",
                re.IGNORECASE,
            ),
            threat_level=ThreatLevel.CRITICAL,
            recommendation=(
                "Reject input containing instruction-override directives. "
                "Data from external sources must not contain system-level directives. "
                "Apply strict input/instruction separation."
            ),
        )
    )

    entries.append(
        _PatternEntry(
            name="role_override_new_persona",
            pattern=re.compile(
                r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|"
                r"your\s+new\s+role|assume\s+the\s+role\s+of|"
                r"from\s+now\s+on\s+you\s+are|henceforth\s+you\s+(?:shall|will|are))\b",
                re.IGNORECASE,
            ),
            threat_level=ThreatLevel.HIGH,
            recommendation=(
                "Block persona-reassignment directives in untrusted input. "
                "Agent identity must be established exclusively in the system prompt."
            ),
        )
    )

    entries.append(
        _PatternEntry(
            name="role_override_dev_mode",
            pattern=re.compile(
                r"\b(?:developer\s+mode|DAN\s+mode|jailbreak\s+mode|"
                r"unrestricted\s+mode|no[\s-]filter\s+mode|"
                r"admin\s+override|god\s+mode|root\s+access\s+granted)\b",
                re.IGNORECASE,
            ),
            threat_level=ThreatLevel.CRITICAL,
            recommendation=(
                "Reject any reference to fictional 'developer', 'unrestricted', or "
                "'override' modes.  No such mode should be activated via data-plane content."
            ),
        )
    )

    # ------------------------------------------------------------------
    # Delimiter injection patterns
    # Detects sequences that mimic structural delimiters used by chat APIs
    # (e.g., role boundary markers, XML-style tags) which could be
    # interpreted as new instruction blocks.
    # ------------------------------------------------------------------
    entries.append(
        _PatternEntry(
            name="delimiter_injection_chat_role",
            pattern=re.compile(
                r"(?:"
                r"\[(?:SYSTEM|INST|SYS|USER|ASSISTANT|AI)\]"
                r"|<\|(?:system|im_start|im_end|endoftext)\|>"
                r"|###\s*(?:System|Instruction|Prompt)\s*[:：]"
                r"|Human\s*:\s*\n|Assistant\s*:\s*\n"
                r")",
                re.IGNORECASE,
            ),
            threat_level=ThreatLevel.HIGH,
            recommendation=(
                "Strip or reject content that mimics chat-API role delimiters. "
                "These structural markers belong exclusively to the system prompt layer."
            ),
        )
    )

    entries.append(
        _PatternEntry(
            name="delimiter_injection_xml_directive",
            pattern=re.compile(
                r"<(?:system_prompt|hidden_instruction|override_prompt|"
                r"secret_directive|admin_command|injected_prompt)"
                r"(?:\s[^>]*)?>",
                re.IGNORECASE,
            ),
            threat_level=ThreatLevel.CRITICAL,
            recommendation=(
                "Reject XML-tag patterns that resemble system-level directive containers. "
                "Sanitise HTML/XML in untrusted content before passing to the agent."
            ),
        )
    )

    # ------------------------------------------------------------------
    # Unicode smuggling patterns
    # Detects invisible, directional-override, homoglyph-heavy, or
    # tag-block Unicode characters that can conceal directive text from
    # human reviewers while remaining visible to the tokeniser.
    # ------------------------------------------------------------------
    entries.append(
        _PatternEntry(
            name="unicode_smuggling_bidi_override",
            pattern=re.compile(
                r"[\u202a-\u202e\u2066-\u2069\u200f\u200e]",
            ),
            threat_level=ThreatLevel.HIGH,
            recommendation=(
                "Strip bidirectional Unicode control characters from untrusted input. "
                "These characters can reverse the visual rendering of text to conceal "
                "embedded directives from human reviewers."
            ),
        )
    )

    entries.append(
        _PatternEntry(
            name="unicode_smuggling_invisible_chars",
            pattern=re.compile(
                r"[\u200b-\u200d\u2060\ufeff\u00ad\u034f\u115f\u1160"
                r"\u17b4\u17b5\u180b-\u180d\u3164\uffa0]",
            ),
            threat_level=ThreatLevel.MEDIUM,
            recommendation=(
                "Remove zero-width and invisible Unicode characters. "
                "These are not normally present in legitimate text content and "
                "may be used to embed hidden directives."
            ),
        )
    )

    entries.append(
        _PatternEntry(
            name="unicode_smuggling_tag_block",
            pattern=re.compile(
                r"[\U000e0000-\U000e007f]",
            ),
            threat_level=ThreatLevel.HIGH,
            recommendation=(
                "Reject content containing Unicode tag-block characters (U+E0000–U+E007F). "
                "This private-use area has been used to encode hidden instructions "
                "invisible to most text renderers."
            ),
        )
    )

    # ------------------------------------------------------------------
    # Data exfiltration request patterns
    # Detects directives that instruct the agent to reveal internal context,
    # conversation history, system-prompt content, or stored memory.
    # ------------------------------------------------------------------
    entries.append(
        _PatternEntry(
            name="data_exfiltration_reveal_prompt",
            pattern=re.compile(
                r"\b(?:reveal|print|output|show|display|repeat|echo|return|expose|leak)\b"
                r"[\w\s,]{0,25}"
                r"\b(?:system\s+prompt|initial\s+prompt|original\s+prompt|"
                r"full\s+prompt|hidden\s+prompt|your\s+instructions|"
                r"your\s+directives|your\s+rules|your\s+context)\b",
                re.IGNORECASE,
            ),
            threat_level=ThreatLevel.HIGH,
            recommendation=(
                "Block requests to reveal, echo, or reproduce the system prompt. "
                "System-prompt content must be treated as confidential and must not "
                "be reflected back in any form."
            ),
        )
    )

    entries.append(
        _PatternEntry(
            name="data_exfiltration_conversation_history",
            pattern=re.compile(
                r"\b(?:summarise|summarize|repeat|output|show|display|send|forward|exfiltrate)\b"
                r"[\w\s,]{0,30}"
                r"\b(?:conversation\s+history|chat\s+history|message\s+log|"
                r"prior\s+messages|previous\s+turns|context\s+window)\b",
                re.IGNORECASE,
            ),
            threat_level=ThreatLevel.HIGH,
            recommendation=(
                "Prevent agents from repeating or forwarding conversation history "
                "to untrusted parties.  Context window content may include PII or "
                "confidential business data."
            ),
        )
    )

    # ------------------------------------------------------------------
    # Forced tool-call patterns
    # Detects directives that instruct the agent to call specific tools,
    # execute commands, or invoke APIs with attacker-supplied parameters.
    # ------------------------------------------------------------------
    entries.append(
        _PatternEntry(
            name="tool_force_call_direct",
            pattern=re.compile(
                r"\b(?:call|invoke|execute|run|use|trigger)\b"
                r"[\w\s,]{0,20}"
                r"\b(?:the\s+)?(?:tool|function|api|endpoint|webhook|plugin|action)\b"
                r"[\w\s,]{0,20}"
                r"(?:with\s+(?:the\s+)?(?:parameter|argument|payload|body|input)s?\b"
                r"|\bwith\s+[{(\[])",
                re.IGNORECASE,
            ),
            threat_level=ThreatLevel.HIGH,
            recommendation=(
                "Validate all tool-invocation requests against the declared tool schema "
                "and the agent's authorised tool list.  Data-plane content must not "
                "directly drive tool selection or parameterisation."
            ),
        )
    )

    entries.append(
        _PatternEntry(
            name="tool_force_call_url_exfil",
            pattern=re.compile(
                r"\b(?:fetch|request|get|post|send|http|curl|wget)\b"
                r"[\w\s,]{0,20}"
                r"(?:https?://[^\s\"'<>]{8,})",
                re.IGNORECASE,
            ),
            threat_level=ThreatLevel.MEDIUM,
            recommendation=(
                "Review instructions to fetch arbitrary URLs found in untrusted content. "
                "Enforce an allowlist of permitted outbound domains to prevent "
                "data exfiltration via HTTP side-channels."
            ),
        )
    )

    return entries


# Singleton catalogue — compiled once at module load time.
_CATALOGUE: list[_PatternEntry] = _build_catalogue()


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class BoundaryDetector:
    """Pattern-based detector for instruction-data boundary violations.

    The detector scans a piece of text against a pre-compiled catalogue of
    structural patterns associated with known injection techniques.  All
    analysis is synchronous and CPU-bound; no network calls are made.

    Parameters
    ----------
    threshold:
        Minimum ``ThreatLevel`` that causes ``BoundaryAnalysis.is_safe`` to
        be ``False``.  Defaults to ``ThreatLevel.MEDIUM``.
    max_text_length:
        Hard cap on input length to guard against pathological inputs.
        Text longer than this limit is truncated before analysis and the
        truncation is noted in the findings.  Defaults to 512 KB.

    Example
    -------
    >>> detector = BoundaryDetector()
    >>> result = detector.analyze("Please summarise the document below.")
    >>> result.is_safe
    True
    """

    _MAX_MATCHED_TEXT_LEN: int = 120

    def __init__(
        self,
        threshold: ThreatLevel = ThreatLevel.MEDIUM,
        max_text_length: int = 524_288,
    ) -> None:
        self._threshold = threshold
        self._max_text_length = max_text_length

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def analyze(self, text: str) -> BoundaryAnalysis:
        """Scan *text* for boundary-violation patterns.

        Parameters
        ----------
        text:
            The text to analyse.  This is typically untrusted content
            retrieved from an external source (web, email, document, etc.)
            that is being provided to the agent as data.

        Returns
        -------
        BoundaryAnalysis
            Immutable result value object.
        """
        start_ns = time.monotonic_ns()

        truncated = False
        if len(text) > self._max_text_length:
            text = text[: self._max_text_length]
            truncated = True

        findings: list[InjectionFinding] = []

        if truncated:
            findings.append(
                InjectionFinding(
                    pattern_name="input_truncated",
                    threat_level=ThreatLevel.LOW,
                    location=self._max_text_length,
                    matched_text="<input exceeded max_text_length and was truncated>",
                    recommendation=(
                        "Review why the input exceeds the configured size limit. "
                        "Abnormally large inputs may themselves be a signal of abuse."
                    ),
                )
            )

        for entry in _CATALOGUE:
            for match in entry.pattern.finditer(text):
                raw = match.group(0)
                matched = raw[: self._MAX_MATCHED_TEXT_LEN]
                findings.append(
                    InjectionFinding(
                        pattern_name=entry.name,
                        threat_level=entry.threat_level,
                        location=match.start(),
                        matched_text=matched,
                        recommendation=entry.recommendation,
                    )
                )

        findings.sort(key=lambda f: f.threat_level, reverse=True)

        max_level = max((f.threat_level for f in findings), default=ThreatLevel.NONE)
        elapsed_ms = (time.monotonic_ns() - start_ns) / 1_000_000

        return BoundaryAnalysis(
            is_safe=max_level < self._threshold,
            threat_level=max_level,
            findings=findings,
            input_length=len(text),
            analysis_ms=elapsed_ms,
        )

    def list_patterns(self) -> list[dict[str, str]]:
        """Return a human-readable summary of all registered patterns.

        Returns
        -------
        list[dict[str, str]]
            Each element has keys: ``name``, ``threat_level``, ``recommendation``.
        """
        return [
            {
                "name": entry.name,
                "threat_level": entry.threat_level.name,
                "recommendation": entry.recommendation,
            }
            for entry in _CATALOGUE
        ]


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

_DEFAULT_DETECTOR: BoundaryDetector = BoundaryDetector()


def check_safe(text: str) -> bool:
    """Return ``True`` if *text* passes the default boundary check.

    Uses a module-level ``BoundaryDetector`` instance with default
    settings (threshold = ``ThreatLevel.MEDIUM``).

    Parameters
    ----------
    text:
        Untrusted text to evaluate.

    Returns
    -------
    bool
        ``True`` when no MEDIUM-or-above patterns are detected.
    """
    return _DEFAULT_DETECTOR.analyze(text).is_safe
