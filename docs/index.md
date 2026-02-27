# aumos-owasp-defenses

OWASP ASI Top 10 Defensive Implementations — protect agents from prompt injection to rogue agents.

[![CI](https://github.com/invincible-jha/aumos-owasp-defenses/actions/workflows/ci.yaml/badge.svg)](https://github.com/invincible-jha/aumos-owasp-defenses/actions/workflows/ci.yaml)
[![PyPI version](https://img.shields.io/pypi/v/aumos-owasp-defenses.svg)](https://pypi.org/project/aumos-owasp-defenses/)
[![Python versions](https://img.shields.io/pypi/pyversions/aumos-owasp-defenses.svg)](https://pypi.org/project/aumos-owasp-defenses/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## Installation

```bash
pip install aumos-owasp-defenses
```

Verify the installation:

```bash
aumos-owasp-defenses version
```

---

## Quick Start

```python
from aumos_owasp_defenses import AgentScanner

# Scan an agent configuration against all 10 OWASP ASI categories
agent_config = {
    "name": "my-agent",
    "tools": ["web_search", "file_read"],
    "llm": "gpt-4o",
    "max_iterations": 10,
    "output_schema": True,
    "rate_limiting": True,
}

scanner = AgentScanner()
result = scanner.scan(agent_config, profile="standard")

print(f"Overall grade: {result.grade}")        # e.g. "B"
print(f"Score: {result.overall_score:.1f}%")

for category, findings in result.categories.items():
    print(f"\n{category}: {findings.score:.1f}%")
    for recommendation in findings.recommendations:
        print(f"  - {recommendation}")
```

---

## Key Features

- **Ten discrete defense modules** — aligned to the OWASP Agentic Security Top 10 (ASI-01 through ASI-10), each independently importable and composable
- **`AgentScanner`** — performs structural analysis of an agent configuration dict and scores all ten ASI categories with findings, recommendations, and a letter grade (A-F)
- **Four scan profiles** — `standard`, `quick`, `mcp_focused`, and `compliance` (stricter thresholds) — so CI pipelines can tune thoroughness vs. speed
- **Defense primitives** — `BoundaryDetector`, `SchemaValidator`, `RateLimiter`, `CapabilityChecker`, `VendorVerifier`, `ScopeLimiter`, `ProvenanceTracker`, `MessageValidator`, `CircuitBreaker`, `TrustVerifier`, `BaselineProfiler`, and `DriftDetector`
- **Middleware guards** — for LangChain, CrewAI, and generic ASGI/callable stacks that wrap existing agents without requiring internal changes
- **agentcore bridge** — hooks the scanner into the `EventBus` so defense checks fire automatically on lifecycle events
- **Report generator** — produces per-category results with actionable remediation steps in JSON or Markdown

---

## Links

- [GitHub Repository](https://github.com/invincible-jha/aumos-owasp-defenses)
- [PyPI Package](https://pypi.org/project/aumos-owasp-defenses/)
- [Architecture](architecture.md)
- [Changelog](https://github.com/invincible-jha/aumos-owasp-defenses/blob/main/CHANGELOG.md)
- [Contributing](https://github.com/invincible-jha/aumos-owasp-defenses/blob/main/CONTRIBUTING.md)

---

> Part of the [AumOS](https://github.com/aumos-ai) open-source agent infrastructure portfolio.
