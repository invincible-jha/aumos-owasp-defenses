"""aumos-owasp-defenses — OWASP Agentic Security Initiative (ASI) Top 10
defensive reference implementations for AI agents.

Public API
----------
The stable public surface is everything exported from this module.
Anything inside submodules not re-exported here is considered private
and may change without notice.

Quick start
-----------
>>> import aumos_owasp_defenses as owasp
>>> owasp.__version__
'0.1.0'

>>> # ASI-01: Check text for instruction-data boundary violations
>>> owasp.check_safe("Summarise the report below.")
True

>>> # ASI-02: Validate tool call arguments
>>> from aumos_owasp_defenses import SchemaValidator, ToolSchema, ParameterSpec
>>> schema = ToolSchema("search", [ParameterSpec("query", "string", max_length=200)])
>>> validator = SchemaValidator([schema])
>>> validator.validate("search", {"query": "Python type hints"}).is_valid
True

>>> # Run a full scan on an agent config
>>> from aumos_owasp_defenses import AgentScanner
>>> scanner = AgentScanner()
>>> result = scanner.scan({"agent_id": "demo", "system_prompt": "You are a helper."})
>>> result.grade in ("A", "B", "C", "D", "F")
True

OWASP ASI Top 10 Coverage
--------------------------
ASI-01  Goal and Task Hijacking          BoundaryDetector
ASI-02  Tool and Resource Misuse         SchemaValidator, RateLimiter
ASI-03  Identity and Privilege           CapabilityChecker
ASI-04  Supply Chain Risks               VendorVerifier
ASI-05  Insecure Code Execution          ScopeLimiter
ASI-06  Memory Poisoning                 ProvenanceTracker
ASI-07  Inter-Agent Trust               MessageValidator
ASI-08  Cascading Failures               CircuitBreaker
ASI-09  Context Trust Exploitation       TrustVerifier
ASI-10  Rogue Agent Behaviors            BaselineProfiler, DriftDetector
"""
from __future__ import annotations

__version__: str = "0.1.0"

# ---------------------------------------------------------------------------
# ASI-01: Goal and Task Hijacking
# ---------------------------------------------------------------------------
from aumos_owasp_defenses.defenses.asi01_goal_hijack import (
    BoundaryAnalysis,
    BoundaryDetector,
    InjectionFinding,
    ThreatLevel,
    check_safe,
)

# ---------------------------------------------------------------------------
# ASI-02: Tool and Resource Misuse
# ---------------------------------------------------------------------------
from aumos_owasp_defenses.defenses.asi02_tool_misuse import (
    ParameterSpec,
    RateLimitResult,
    RateLimiter,
    SchemaViolation,
    SchemaValidator,
    ToolSchema,
    ValidationResult,
)

# ---------------------------------------------------------------------------
# ASI-03: Identity and Privilege Compromise
# ---------------------------------------------------------------------------
from aumos_owasp_defenses.defenses.asi03_identity_privilege import (
    AgentCapabilityProfile,
    CapabilityChecker,
    PermissionResult,
)

# ---------------------------------------------------------------------------
# ASI-04: Supply Chain and Dependency Risks
# ---------------------------------------------------------------------------
from aumos_owasp_defenses.defenses.asi04_supply_chain import (
    AllowlistEntry,
    VendorVerifier,
    VerificationResult,
)

# ---------------------------------------------------------------------------
# ASI-05: Insecure Code Execution
# ---------------------------------------------------------------------------
from aumos_owasp_defenses.defenses.asi05_code_execution import (
    CommandCheckResult,
    PathCheckResult,
    ScopeLimiter,
)

# ---------------------------------------------------------------------------
# ASI-06: Memory and Context Manipulation
# ---------------------------------------------------------------------------
from aumos_owasp_defenses.defenses.asi06_memory_poisoning import (
    ChainVerificationResult,
    ProvenanceRecord,
    ProvenanceTracker,
    SourceTrustLevel,
)

# ---------------------------------------------------------------------------
# ASI-07: Inter-Agent Trust Exploitation
# ---------------------------------------------------------------------------
from aumos_owasp_defenses.defenses.asi07_inter_agent import (
    AgentTrustLevel,
    FieldSpec,
    MessageSchema,
    MessageValidationResult,
    MessageValidator,
)

# ---------------------------------------------------------------------------
# ASI-08: Cascading and Recursive Failures
# ---------------------------------------------------------------------------
from aumos_owasp_defenses.defenses.asi08_cascading_failures import (
    CallResult,
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
)

# ---------------------------------------------------------------------------
# ASI-09: Context Trust Exploitation
# ---------------------------------------------------------------------------
from aumos_owasp_defenses.defenses.asi09_trust_exploitation import (
    AgentTrustProfile,
    ClaimVerificationResult,
    DelegationResult,
    EscalationCheckResult,
    TrustTier,
    TrustVerifier,
)

# ---------------------------------------------------------------------------
# ASI-10: Rogue / Emergent Agent Behaviors
# ---------------------------------------------------------------------------
from aumos_owasp_defenses.defenses.asi10_rogue_agents import (
    AgentBaseline,
    BaselineProfiler,
    DriftCheckResult,
    DriftDetector,
    DriftSeverity,
    MetricBaseline,
    MetricDriftFinding,
)

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
from aumos_owasp_defenses.middleware.guard import (
    GuardResult,
    OWASPGuard,
    SecurityConfig,
    SecurityViolation,
)

# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
from aumos_owasp_defenses.scanner.agent_scanner import (
    AgentScanner,
    CategoryResult,
    ScanProfile,
    ScanResult,
)
from aumos_owasp_defenses.scanner.report_generator import ReportGenerator

# ---------------------------------------------------------------------------
# __all__
# ---------------------------------------------------------------------------

__all__ = [
    "__version__",
    # ASI-01
    "BoundaryAnalysis",
    "BoundaryDetector",
    "InjectionFinding",
    "ThreatLevel",
    "check_safe",
    # ASI-02
    "ParameterSpec",
    "RateLimitResult",
    "RateLimiter",
    "SchemaViolation",
    "SchemaValidator",
    "ToolSchema",
    "ValidationResult",
    # ASI-03
    "AgentCapabilityProfile",
    "CapabilityChecker",
    "PermissionResult",
    # ASI-04
    "AllowlistEntry",
    "VendorVerifier",
    "VerificationResult",
    # ASI-05
    "CommandCheckResult",
    "PathCheckResult",
    "ScopeLimiter",
    # ASI-06
    "ChainVerificationResult",
    "ProvenanceRecord",
    "ProvenanceTracker",
    "SourceTrustLevel",
    # ASI-07
    "AgentTrustLevel",
    "FieldSpec",
    "MessageSchema",
    "MessageValidationResult",
    "MessageValidator",
    # ASI-08
    "CallResult",
    "CircuitBreaker",
    "CircuitOpenError",
    "CircuitState",
    # ASI-09
    "AgentTrustProfile",
    "ClaimVerificationResult",
    "DelegationResult",
    "EscalationCheckResult",
    "TrustTier",
    "TrustVerifier",
    # ASI-10
    "AgentBaseline",
    "BaselineProfiler",
    "DriftCheckResult",
    "DriftDetector",
    "DriftSeverity",
    "MetricBaseline",
    "MetricDriftFinding",
    # Middleware
    "GuardResult",
    "OWASPGuard",
    "SecurityConfig",
    "SecurityViolation",
    # Scanner
    "AgentScanner",
    "CategoryResult",
    "ReportGenerator",
    "ScanProfile",
    "ScanResult",
]
