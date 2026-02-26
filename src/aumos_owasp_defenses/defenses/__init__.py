"""Defense modules for OWASP Agentic Security Initiative (ASI) Top 10.

Each sub-package addresses one ASI category:

    ASI-01  Goal and Task Hijacking
    ASI-02  Tool and Resource Misuse
    ASI-03  Identity and Privilege Compromise
    ASI-04  Supply Chain and Dependency Risks
    ASI-05  Insecure Code Execution
    ASI-06  Memory and Context Manipulation (Poisoning)
    ASI-07  Inter-Agent Trust Exploitation
    ASI-08  Cascading and Recursive Failures
    ASI-09  Context Trust Exploitation
    ASI-10  Rogue / Emergent Agent Behaviors

All modules expose only rule-based, pattern-matching, and structural
defenses.  No heuristics that require ML model inference are included.
"""
from __future__ import annotations

from aumos_owasp_defenses.defenses.asi01_goal_hijack import BoundaryDetector, BoundaryAnalysis, InjectionFinding, ThreatLevel, check_safe
from aumos_owasp_defenses.defenses.asi02_tool_misuse import SchemaValidator, RateLimiter
from aumos_owasp_defenses.defenses.asi03_identity_privilege import CapabilityChecker
from aumos_owasp_defenses.defenses.asi04_supply_chain import VendorVerifier
from aumos_owasp_defenses.defenses.asi05_code_execution import ScopeLimiter
from aumos_owasp_defenses.defenses.asi06_memory_poisoning import ProvenanceTracker
from aumos_owasp_defenses.defenses.asi07_inter_agent import MessageValidator
from aumos_owasp_defenses.defenses.asi08_cascading_failures import CircuitBreaker
from aumos_owasp_defenses.defenses.asi09_trust_exploitation import TrustVerifier
from aumos_owasp_defenses.defenses.asi10_rogue_agents import BaselineProfiler, DriftDetector

__all__ = [
    # ASI-01
    "BoundaryDetector",
    "BoundaryAnalysis",
    "InjectionFinding",
    "ThreatLevel",
    "check_safe",
    # ASI-02
    "SchemaValidator",
    "RateLimiter",
    # ASI-03
    "CapabilityChecker",
    # ASI-04
    "VendorVerifier",
    # ASI-05
    "ScopeLimiter",
    # ASI-06
    "ProvenanceTracker",
    # ASI-07
    "MessageValidator",
    # ASI-08
    "CircuitBreaker",
    # ASI-09
    "TrustVerifier",
    # ASI-10
    "BaselineProfiler",
    "DriftDetector",
]
