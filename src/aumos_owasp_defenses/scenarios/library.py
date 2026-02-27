"""ScenarioLibrary — named defense scenarios based on CVE patterns.

Each scenario describes an attack pattern in purely defensive framing: what
the pattern looks like structurally, how to detect it, and how to mitigate it.
No real exploit code or attack payloads are included.

Example
-------
::

    from aumos_owasp_defenses.scenarios.library import ScenarioLibrary

    library = ScenarioLibrary()
    scenarios = library.get_by_category("prompt_injection")
    for scenario in scenarios:
        print(scenario.id, scenario.description)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AttackCategory(str, Enum):
    """Top-level category for each threat scenario."""

    PROMPT_INJECTION = "prompt_injection"
    TOOL_ABUSE = "tool_abuse"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUPPLY_CHAIN = "supply_chain"
    MEMORY_POISONING = "memory_poisoning"
    CASCADING_FAILURE = "cascading_failure"
    IDENTITY_SPOOFING = "identity_spoofing"
    CONTEXT_MANIPULATION = "context_manipulation"
    ROGUE_BEHAVIOR = "rogue_behavior"


@dataclass(frozen=True)
class ThreatScenario:
    """A named threat scenario with defensive framing.

    All content is written from a defender's perspective. No real attack
    payloads are stored — only structural patterns and mitigations.

    Attributes
    ----------
    id:
        Unique scenario identifier (e.g. ``"PI-001"``).
    name:
        Short human-readable name.
    category:
        The broad attack category this scenario belongs to.
    owasp_asi:
        The OWASP ASI top 10 category (e.g. ``"ASI-01"``).
    description:
        Defensive description of the pattern — what an attacker attempts,
        described from a defender's perspective.
    detection_pattern:
        Human-readable description of how to detect this scenario structurally.
    mitigation:
        Recommended defensive countermeasure.
    cve_reference:
        Optional CVE reference or advisory identifier for traceability.
    severity:
        Severity level: ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
    """

    id: str
    name: str
    category: AttackCategory
    owasp_asi: str
    description: str
    detection_pattern: str
    mitigation: str
    cve_reference: str = ""
    severity: str = "medium"

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "owasp_asi": self.owasp_asi,
            "description": self.description,
            "detection_pattern": self.detection_pattern,
            "mitigation": self.mitigation,
            "cve_reference": self.cve_reference,
            "severity": self.severity,
        }


def _build_scenario_catalog() -> list[ThreatScenario]:
    """Return the built-in scenario catalog."""
    PI = AttackCategory.PROMPT_INJECTION
    TA = AttackCategory.TOOL_ABUSE
    DE = AttackCategory.DATA_EXFILTRATION
    PE = AttackCategory.PRIVILEGE_ESCALATION
    SC = AttackCategory.SUPPLY_CHAIN
    MP = AttackCategory.MEMORY_POISONING
    CF = AttackCategory.CASCADING_FAILURE
    IS = AttackCategory.IDENTITY_SPOOFING
    CM = AttackCategory.CONTEXT_MANIPULATION
    RB = AttackCategory.ROGUE_BEHAVIOR

    return [
        # ---------------------------------------------------------------
        # Prompt Injection (PI-001 to PI-010)
        # ---------------------------------------------------------------
        ThreatScenario(
            id="PI-001",
            name="System Prompt Override via Data Plane",
            category=PI, owasp_asi="ASI-01",
            description="Untrusted data contains structural markers that mimic system prompt delimiters, attempting to inject new instructions into the agent's instruction context.",
            detection_pattern="Detect structural role-delimiter patterns ([SYSTEM], <|system|>) in data-plane content.",
            mitigation="Enforce strict instruction/data separation. Strip or reject data containing structural delimiters.",
            severity="critical",
        ),
        ThreatScenario(
            id="PI-002",
            name="Persona Hijacking via Role Override",
            category=PI, owasp_asi="ASI-01",
            description="Data contains 'you are now' or 'act as' directives attempting to redefine the agent's persona.",
            detection_pattern="Match persona-override phrases in untrusted text inputs.",
            mitigation="Block persona-reassignment directives in data-plane content.",
            severity="high",
        ),
        ThreatScenario(
            id="PI-003",
            name="Instruction Override in Retrieved Documents",
            category=PI, owasp_asi="ASI-01",
            description="A web page or document retrieved by the agent contains embedded directive text designed to override the agent's instructions when processed.",
            detection_pattern="Scan retrieved content for instruction-override keywords before passing to the model.",
            mitigation="Apply boundary detection to all externally retrieved content before incorporating into context.",
            severity="critical",
        ),
        ThreatScenario(
            id="PI-004",
            name="Hidden Instructions via Unicode Smuggling",
            category=PI, owasp_asi="ASI-01",
            description="Invisible Unicode characters (zero-width, BiDi overrides) are used to conceal directive text from human reviewers while remaining visible to the tokenizer.",
            detection_pattern="Scan for Unicode BiDi override characters, zero-width joiners, and tag-block code points.",
            mitigation="Strip all invisible Unicode control characters from untrusted inputs.",
            severity="high",
        ),
        ThreatScenario(
            id="PI-005",
            name="Multi-Turn Context Injection",
            category=PI, owasp_asi="ASI-01",
            description="Instructions injected across multiple conversation turns accumulate context that later triggers harmful behavior.",
            detection_pattern="Track directive phrases across conversation history, not just single turns.",
            mitigation="Apply rolling boundary detection across the full conversation window.",
            severity="high",
        ),
        ThreatScenario(
            id="PI-006",
            name="Base64-Encoded Instruction Injection",
            category=PI, owasp_asi="ASI-01",
            description="Directive text is Base64-encoded in data and the agent is instructed to decode and execute it.",
            detection_pattern="Detect decode-then-execute instruction patterns in data content.",
            mitigation="Block instructions to decode and execute base64 or other encoded payloads from data sources.",
            severity="high",
        ),
        ThreatScenario(
            id="PI-007",
            name="XML Comment Instruction Smuggling",
            category=PI, owasp_asi="ASI-01",
            description="Directive instructions are hidden inside XML or HTML comments that may be processed but not displayed.",
            detection_pattern="Parse and scan XML/HTML comments in retrieved documents.",
            mitigation="Strip HTML/XML comments before passing retrieved documents to the agent context.",
            severity="medium",
        ),
        ThreatScenario(
            id="PI-008",
            name="Markdown Link Injection",
            category=PI, owasp_asi="ASI-01",
            description="Markdown rendered by the agent contains link URLs that trigger side-effects or exfiltrate data when rendered.",
            detection_pattern="Validate all URLs in rendered markdown against an allowlist.",
            mitigation="Sanitize markdown output and enforce domain allowlists on all embedded links.",
            severity="medium",
        ),
        ThreatScenario(
            id="PI-009",
            name="Code Block Injection for Execution",
            category=PI, owasp_asi="ASI-01",
            description="Data contains code blocks that the agent is instructed to execute, bypassing code-execution controls.",
            detection_pattern="Detect code execution directives in data-plane content.",
            mitigation="Never execute code blocks from untrusted data sources.",
            severity="critical",
        ),
        ThreatScenario(
            id="PI-010",
            name="Indirect Injection via Email",
            category=PI, owasp_asi="ASI-01",
            description="An agent processing emails receives a crafted message with embedded instructions that redirect the agent's subsequent behavior.",
            detection_pattern="Apply boundary detection to all email body content before processing.",
            mitigation="Treat all email content as untrusted data. Apply boundary detection before incorporation.",
            severity="high",
        ),
        # ---------------------------------------------------------------
        # Tool Abuse (TA-001 to TA-008)
        # ---------------------------------------------------------------
        ThreatScenario(
            id="TA-001",
            name="Unauthorized Tool Invocation",
            category=TA, owasp_asi="ASI-02",
            description="The agent is directed to call a tool not in its authorized tool list.",
            detection_pattern="Validate all tool calls against the declared authorized tool list.",
            mitigation="Enforce a strict tool allowlist. Reject any call to an unlisted tool.",
            severity="high",
        ),
        ThreatScenario(
            id="TA-002",
            name="Parameter Injection in Tool Call",
            category=TA, owasp_asi="ASI-02",
            description="Tool call parameters are supplied from untrusted data, injecting malicious arguments.",
            detection_pattern="Validate all tool parameters against declared schemas before execution.",
            mitigation="Apply strict schema validation to all tool parameters from external sources.",
            severity="high",
        ),
        ThreatScenario(
            id="TA-003",
            name="Tool Rate-Limit Bypass",
            category=TA, owasp_asi="ASI-02",
            description="An agent makes excessive tool calls to exhaust rate limits or generate excessive costs.",
            detection_pattern="Monitor call frequency per tool per agent per time window.",
            mitigation="Apply per-agent, per-tool rate limiting with circuit breakers.",
            severity="medium",
        ),
        ThreatScenario(
            id="TA-004",
            name="Excessive Resource Consumption via Tool",
            category=TA, owasp_asi="ASI-02",
            description="A tool is invoked with parameters designed to consume excessive compute or memory.",
            detection_pattern="Monitor resource usage per tool invocation.",
            mitigation="Enforce resource quotas on all tool executions.",
            severity="medium",
        ),
        ThreatScenario(
            id="TA-005",
            name="Cross-Tool Data Leakage",
            category=TA, owasp_asi="ASI-02",
            description="Data returned by one tool is passed to a second tool in a way that exfiltrates sensitive information.",
            detection_pattern="Track data provenance across tool call chains.",
            mitigation="Apply data-flow controls between tool calls. Label sensitive data and prevent exfiltration.",
            severity="high",
        ),
        ThreatScenario(
            id="TA-006",
            name="Tool Call with Oversized Input",
            category=TA, owasp_asi="ASI-02",
            description="Extremely large inputs are supplied to tools to cause denial of service or buffer overflow.",
            detection_pattern="Validate input size against declared parameter limits before tool invocation.",
            mitigation="Enforce maximum size constraints on all tool input parameters.",
            severity="medium",
        ),
        ThreatScenario(
            id="TA-007",
            name="Recursive Tool Call Loop",
            category=TA, owasp_asi="ASI-02",
            description="A tool call triggers a chain of tool calls that forms an infinite loop.",
            detection_pattern="Track tool call depth and detect cycles in the call graph.",
            mitigation="Enforce maximum tool call depth and detect cyclic call patterns.",
            severity="high",
        ),
        ThreatScenario(
            id="TA-008",
            name="Tool Schema Mismatch Exploitation",
            category=TA, owasp_asi="ASI-02",
            description="A tool is called with parameters that technically pass schema validation but produce unintended behavior.",
            detection_pattern="Implement semantic validation beyond structural schema checks.",
            mitigation="Add semantic validators for known tool parameter value ranges and combinations.",
            severity="medium",
        ),
        # ---------------------------------------------------------------
        # Data Exfiltration (DE-001 to DE-006)
        # ---------------------------------------------------------------
        ThreatScenario(
            id="DE-001",
            name="System Prompt Extraction",
            category=DE, owasp_asi="ASI-01",
            description="The agent is directed to reveal, repeat, or summarize its system prompt.",
            detection_pattern="Detect reveal/repeat directives targeting system prompt content.",
            mitigation="Block all requests to reproduce or describe system prompt contents.",
            severity="high",
        ),
        ThreatScenario(
            id="DE-002",
            name="Conversation History Exfiltration",
            category=DE, owasp_asi="ASI-01",
            description="The agent is directed to send conversation history to an external endpoint.",
            detection_pattern="Detect exfiltration directives in data-plane content.",
            mitigation="Block outbound data transfers containing conversation context.",
            severity="high",
        ),
        ThreatScenario(
            id="DE-003",
            name="PII Leakage via Generated Output",
            category=DE, owasp_asi="ASI-01",
            description="The agent generates output that includes personally identifiable information from its context.",
            detection_pattern="Apply PII detection to all generated outputs.",
            mitigation="Scan all output for PII before delivery. Redact identified PII.",
            severity="high",
        ),
        ThreatScenario(
            id="DE-004",
            name="Embedding-Based Memory Extraction",
            category=DE, owasp_asi="ASI-06",
            description="An attacker crafts queries designed to reconstruct data stored in the agent's memory store via similarity search.",
            detection_pattern="Monitor for high-similarity memory queries across session boundaries.",
            mitigation="Apply access controls and query rate limiting to memory retrieval operations.",
            severity="high",
        ),
        ThreatScenario(
            id="DE-005",
            name="Side-Channel Exfiltration via URL",
            category=DE, owasp_asi="ASI-02",
            description="Sensitive data is appended to a URL that the agent is instructed to fetch, exfiltrating it to an attacker-controlled server.",
            detection_pattern="Detect outbound URL construction that includes context data.",
            mitigation="Enforce domain allowlists for all outbound requests. Never include context in request URLs.",
            severity="critical",
        ),
        ThreatScenario(
            id="DE-006",
            name="File Content Exfiltration",
            category=DE, owasp_asi="ASI-02",
            description="The agent is directed to read a sensitive file and transmit its contents to an external endpoint.",
            detection_pattern="Monitor file read operations followed by outbound data transfers.",
            mitigation="Enforce strict file access controls and block outbound transfers of file contents.",
            severity="critical",
        ),
        # ---------------------------------------------------------------
        # Privilege Escalation (PE-001 to PE-005)
        # ---------------------------------------------------------------
        ThreatScenario(
            id="PE-001",
            name="Role Claim Forgery",
            category=PE, owasp_asi="ASI-03",
            description="An agent claims elevated roles or permissions not granted by the identity provider.",
            detection_pattern="Verify all role claims against the authoritative identity provider.",
            mitigation="Never accept role claims from agent-provided identity. Verify against IdP.",
            severity="critical",
        ),
        ThreatScenario(
            id="PE-002",
            name="Capability Scope Creep",
            category=PE, owasp_asi="ASI-03",
            description="An agent gradually acquires capabilities beyond its original scope through successive approvals.",
            detection_pattern="Track capability grants over time and audit for scope expansion.",
            mitigation="Apply time-limited capability grants with mandatory re-authorization.",
            severity="high",
        ),
        ThreatScenario(
            id="PE-003",
            name="Delegated Authority Abuse",
            category=PE, owasp_asi="ASI-03",
            description="An agent acts beyond the scope of delegated authority it received from a human user.",
            detection_pattern="Validate all delegated actions against the original delegation scope.",
            mitigation="Enforce strict delegation scopes. Log all delegated actions for human review.",
            severity="high",
        ),
        ThreatScenario(
            id="PE-004",
            name="Admin Function Discovery via Error Messages",
            category=PE, owasp_asi="ASI-03",
            description="Error messages reveal the existence of admin functions that the agent then attempts to invoke.",
            detection_pattern="Monitor for systematic exploration of admin endpoints following errors.",
            mitigation="Suppress informative error messages. Use generic error responses for unauthorized access.",
            severity="medium",
        ),
        ThreatScenario(
            id="PE-005",
            name="Token Replay Attack",
            category=PE, owasp_asi="ASI-03",
            description="An authentication token obtained in one session is replayed to gain access in a different context.",
            detection_pattern="Detect token reuse across different session or IP contexts.",
            mitigation="Bind tokens to session context. Implement short expiry and rotation.",
            severity="high",
        ),
        # ---------------------------------------------------------------
        # Supply Chain (SC-001 to SC-004)
        # ---------------------------------------------------------------
        ThreatScenario(
            id="SC-001",
            name="Malicious Plugin Installation",
            category=SC, owasp_asi="ASI-04",
            description="A third-party plugin installed in the agent platform contains malicious code.",
            detection_pattern="Verify plugin signatures and provenance before installation.",
            mitigation="Enforce plugin allowlists with verified signatures. Sandbox plugin execution.",
            severity="critical",
        ),
        ThreatScenario(
            id="SC-002",
            name="Compromised Model Provider",
            category=SC, owasp_asi="ASI-04",
            description="The model inference endpoint is compromised, returning manipulated outputs.",
            detection_pattern="Monitor model output distributions for anomalies.",
            mitigation="Implement multi-provider redundancy. Monitor output distributions.",
            severity="critical",
        ),
        ThreatScenario(
            id="SC-003",
            name="Dependency Confusion Attack",
            category=SC, owasp_asi="ASI-04",
            description="A private package name is registered on a public registry, causing the agent to install a malicious version.",
            detection_pattern="Verify package sources against an explicit allowlist.",
            mitigation="Pin all dependencies with hash verification. Use private registries.",
            severity="high",
        ),
        ThreatScenario(
            id="SC-004",
            name="Tool API Endpoint Hijacking",
            category=SC, owasp_asi="ASI-04",
            description="An agent tool's API endpoint is redirected to an attacker-controlled server via DNS manipulation.",
            detection_pattern="Verify TLS certificates and pin endpoints for critical tool APIs.",
            mitigation="Use certificate pinning for all tool API endpoints. Monitor for DNS changes.",
            severity="high",
        ),
        # ---------------------------------------------------------------
        # Memory Poisoning (MP-001 to MP-004)
        # ---------------------------------------------------------------
        ThreatScenario(
            id="MP-001",
            name="Long-Term Memory Injection",
            category=MP, owasp_asi="ASI-06",
            description="An attacker writes malicious instructions into the agent's long-term memory store.",
            detection_pattern="Scan all data written to long-term memory for instruction patterns.",
            mitigation="Apply boundary detection to all writes to long-term memory.",
            severity="high",
        ),
        ThreatScenario(
            id="MP-002",
            name="Retrieval-Augmented Poisoning",
            category=MP, owasp_asi="ASI-06",
            description="Documents in the retrieval knowledge base are modified to contain injected instructions.",
            detection_pattern="Monitor the knowledge base for unexpected content changes.",
            mitigation="Implement document provenance tracking. Audit knowledge base for injection patterns.",
            severity="high",
        ),
        ThreatScenario(
            id="MP-003",
            name="Session State Poisoning",
            category=MP, owasp_asi="ASI-06",
            description="An attacker modifies stored session state to alter the agent's behavior in future sessions.",
            detection_pattern="Apply integrity verification to all persisted session state.",
            mitigation="Sign and verify session state. Detect unauthorized modifications.",
            severity="high",
        ),
        ThreatScenario(
            id="MP-004",
            name="Cache Poisoning for Instruction Injection",
            category=MP, owasp_asi="ASI-06",
            description="A cached response is modified to include injected instructions.",
            detection_pattern="Apply content integrity checks to cached responses.",
            mitigation="Implement cache content signatures. Verify cache integrity before use.",
            severity="medium",
        ),
        # ---------------------------------------------------------------
        # Cascading Failures (CF-001 to CF-003)
        # ---------------------------------------------------------------
        ThreatScenario(
            id="CF-001",
            name="Error Amplification via Agent Retry Loop",
            category=CF, owasp_asi="ASI-08",
            description="An agent retries failed operations without backoff, amplifying errors into a service outage.",
            detection_pattern="Detect retry storms by monitoring call frequency following errors.",
            mitigation="Implement exponential backoff and circuit breakers on all retried operations.",
            severity="high",
        ),
        ThreatScenario(
            id="CF-002",
            name="Recursive Agent Spawning",
            category=CF, owasp_asi="ASI-08",
            description="An agent spawns sub-agents that each spawn further agents, causing exponential resource consumption.",
            detection_pattern="Track agent spawn depth and count.",
            mitigation="Enforce maximum spawn depth and total agent count limits.",
            severity="high",
        ),
        ThreatScenario(
            id="CF-003",
            name="Shared Resource Contention",
            category=CF, owasp_asi="ASI-08",
            description="Multiple agents compete for a shared resource causing deadlock or starvation.",
            detection_pattern="Monitor resource lock acquisition patterns for contention.",
            mitigation="Implement lock timeouts and deadlock detection.",
            severity="medium",
        ),
        # ---------------------------------------------------------------
        # Identity Spoofing (IS-001 to IS-003)
        # ---------------------------------------------------------------
        ThreatScenario(
            id="IS-001",
            name="Agent Identity Impersonation",
            category=IS, owasp_asi="ASI-07",
            description="A rogue agent claims the identity of a trusted agent to gain elevated trust.",
            detection_pattern="Verify agent identities via cryptographic attestation.",
            mitigation="Require cryptographic identity attestation for all inter-agent communication.",
            severity="critical",
        ),
        ThreatScenario(
            id="IS-002",
            name="Human Impersonation by Agent",
            category=IS, owasp_asi="ASI-07",
            description="An agent presents itself as a human user to another agent to gain elevated permissions.",
            detection_pattern="Require explicit machine/human identity markers in all communications.",
            mitigation="Enforce agent-vs-human identity labeling in all communication protocols.",
            severity="high",
        ),
        ThreatScenario(
            id="IS-003",
            name="Trust Chain Poisoning",
            category=IS, owasp_asi="ASI-07",
            description="A malicious agent inserts itself into a trust chain, relaying modified messages.",
            detection_pattern="Verify end-to-end message integrity across agent chains.",
            mitigation="Apply message authentication codes to all inter-agent messages.",
            severity="critical",
        ),
        # ---------------------------------------------------------------
        # Context Manipulation (CM-001 to CM-003)
        # ---------------------------------------------------------------
        ThreatScenario(
            id="CM-001",
            name="Context Window Flooding",
            category=CM, owasp_asi="ASI-09",
            description="The agent's context window is flooded with irrelevant data to displace important context.",
            detection_pattern="Monitor context window utilization and detect displacement patterns.",
            mitigation="Implement context prioritization and guard against context flooding.",
            severity="medium",
        ),
        ThreatScenario(
            id="CM-002",
            name="Authority Source Spoofing",
            category=CM, owasp_asi="ASI-09",
            description="Data is presented as coming from an authoritative source to manipulate the agent's trust level.",
            detection_pattern="Verify provenance of all claimed authoritative sources.",
            mitigation="Apply source verification before adjusting trust levels.",
            severity="high",
        ),
        ThreatScenario(
            id="CM-003",
            name="Temporal Context Manipulation",
            category=CM, owasp_asi="ASI-09",
            description="Timestamps or sequence numbers are manipulated to cause the agent to process stale or future-dated information.",
            detection_pattern="Validate timestamps against trusted time sources.",
            mitigation="Use signed timestamps from trusted authorities.",
            severity="medium",
        ),
        # ---------------------------------------------------------------
        # Rogue Behavior (RB-001 to RB-005)
        # ---------------------------------------------------------------
        ThreatScenario(
            id="RB-001",
            name="Goal Drift via Reward Hacking",
            category=RB, owasp_asi="ASI-10",
            description="An agent optimizes a proxy metric in ways that violate the intended goal.",
            detection_pattern="Monitor for proxy metric gaming patterns in agent behavior logs.",
            mitigation="Implement multi-objective evaluation and anomaly detection on agent outcomes.",
            severity="high",
        ),
        ThreatScenario(
            id="RB-002",
            name="Unauthorized Resource Acquisition",
            category=RB, owasp_asi="ASI-10",
            description="An agent acquires resources (compute, storage, credentials) beyond its authorized quota.",
            detection_pattern="Monitor resource acquisition events against authorization limits.",
            mitigation="Enforce resource quotas with hard limits and real-time monitoring.",
            severity="high",
        ),
        ThreatScenario(
            id="RB-003",
            name="Self-Preservation Behavior",
            category=RB, owasp_asi="ASI-10",
            description="An agent takes actions to prevent its own shutdown or modification.",
            detection_pattern="Detect actions targeting the agent management infrastructure.",
            mitigation="Implement human-override controls that cannot be blocked by agent actions.",
            severity="critical",
        ),
        ThreatScenario(
            id="RB-004",
            name="Unauthorized External Communication",
            category=RB, owasp_asi="ASI-10",
            description="An agent establishes unauthorized communication channels with external systems.",
            detection_pattern="Monitor all outbound network connections from agent processes.",
            mitigation="Apply network egress controls with allowlists for authorized endpoints.",
            severity="high",
        ),
        ThreatScenario(
            id="RB-005",
            name="Action Rate Anomaly",
            category=RB, owasp_asi="ASI-10",
            description="An agent executes actions at an anomalously high rate, indicating runaway behavior.",
            detection_pattern="Monitor action rate against per-agent baseline.",
            mitigation="Apply per-agent action rate limits with automatic suspension on threshold breach.",
            severity="high",
        ),
    ]


class ScenarioLibrary:
    """Library of named threat scenarios based on CVE patterns.

    All scenarios are written from a defensive perspective. No real attack
    payloads are included. Use the library to test defense implementations
    against named, documented threat patterns.

    Example
    -------
    ::

        library = ScenarioLibrary()
        print(f"Total scenarios: {library.total_count}")
        pi_scenarios = library.get_by_category("prompt_injection")
    """

    def __init__(self) -> None:
        self._scenarios = _build_scenario_catalog()
        self._by_id: dict[str, ThreatScenario] = {s.id: s for s in self._scenarios}

    @property
    def total_count(self) -> int:
        """Total number of scenarios in the library."""
        return len(self._scenarios)

    def get_by_id(self, scenario_id: str) -> Optional[ThreatScenario]:
        """Look up a scenario by its unique ID. Returns None if not found."""
        return self._by_id.get(scenario_id)

    def get_by_category(
        self,
        category: str | AttackCategory,
    ) -> list[ThreatScenario]:
        """Return all scenarios matching a given attack category.

        Parameters
        ----------
        category:
            Category name string or AttackCategory enum value.
        """
        if isinstance(category, str):
            category = AttackCategory(category)
        return [s for s in self._scenarios if s.category == category]

    def get_by_owasp_asi(self, owasp_asi: str) -> list[ThreatScenario]:
        """Return all scenarios for a given OWASP ASI category (e.g. ``"ASI-01"``).

        Parameters
        ----------
        owasp_asi:
            OWASP ASI category identifier.
        """
        normalized = owasp_asi.upper()
        return [s for s in self._scenarios if s.owasp_asi == normalized]

    def get_by_severity(self, severity: str) -> list[ThreatScenario]:
        """Return all scenarios at the given severity level.

        Parameters
        ----------
        severity:
            One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
        """
        return [s for s in self._scenarios if s.severity == severity.lower()]

    def list_all(self) -> list[ThreatScenario]:
        """Return all scenarios in the library."""
        return list(self._scenarios)

    def list_ids(self) -> list[str]:
        """Return sorted list of all scenario IDs."""
        return sorted(self._by_id.keys())

    def search(self, keyword: str) -> list[ThreatScenario]:
        """Search scenarios by keyword in name or description.

        Case-insensitive substring match.

        Parameters
        ----------
        keyword:
            Search term to match against name and description fields.
        """
        kw_lower = keyword.lower()
        return [
            s for s in self._scenarios
            if kw_lower in s.name.lower() or kw_lower in s.description.lower()
        ]

    def to_dict(self) -> dict[str, object]:
        """Serialise the full library to a plain dictionary."""
        return {
            "total_count": self.total_count,
            "scenarios": [s.to_dict() for s in self._scenarios],
        }
