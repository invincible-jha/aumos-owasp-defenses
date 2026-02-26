# aumos-owasp-defenses

OWASP Agentic Security Top 10 defensive implementations

[![CI](https://github.com/aumos-ai/aumos-owasp-defenses/actions/workflows/ci.yaml/badge.svg)](https://github.com/aumos-ai/aumos-owasp-defenses/actions/workflows/ci.yaml)
[![PyPI version](https://img.shields.io/pypi/v/aumos-owasp-defenses.svg)](https://pypi.org/project/aumos-owasp-defenses/)
[![Python versions](https://img.shields.io/pypi/pyversions/aumos-owasp-defenses.svg)](https://pypi.org/project/aumos-owasp-defenses/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Part of the [AumOS](https://github.com/aumos-ai) open-source agent infrastructure portfolio.

---

## Features

- Ten discrete defense modules aligned to the OWASP Agentic Security Top 10 (ASI-01 through ASI-10), each independently importable and composable
- `AgentScanner` performs structural analysis of an agent configuration dict and scores all ten ASI categories with findings, recommendations, and a letter grade (A–F)
- Four scan profiles — `standard`, `quick`, `mcp_focused`, and `compliance` (stricter thresholds) — so CI pipelines can tune thoroughness vs. speed
- Defense primitives include `BoundaryDetector`, `SchemaValidator`, `RateLimiter`, `CapabilityChecker`, `VendorVerifier`, `ScopeLimiter`, `ProvenanceTracker`, `MessageValidator`, `CircuitBreaker`, `TrustVerifier`, `BaselineProfiler`, and `DriftDetector`
- Middleware guards for LangChain, CrewAI, and generic ASGI/callable stacks that wrap existing agents without requiring internal changes
- `agentcore` bridge hooks the scanner into the `EventBus` so defense checks fire automatically on lifecycle events
- Report generator produces per-category results with actionable remediation steps in JSON or Markdown

## Quick Start

Install from PyPI:

```bash
pip install aumos-owasp-defenses
```

Verify the installation:

```bash
aumos-owasp-defenses version
```

Basic usage:

```python
import aumos_owasp_defenses

# See examples/01_quickstart.py for a working example
```

## Documentation

- [Architecture](docs/architecture.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Examples](examples/README.md)

## Enterprise Upgrade

The open-source edition provides the core foundation. For production
deployments requiring SLA-backed support, advanced integrations, and the full
AgentShield platform, see [docs/UPGRADE_TO_AgentShield.md](docs/UPGRADE_TO_AgentShield.md).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
before opening a pull request.

## License

Apache 2.0 — see [LICENSE](LICENSE) for full terms.

---

Part of [AumOS](https://github.com/aumos-ai) — open-source agent infrastructure.
