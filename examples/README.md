# Examples

| # | Example | Description |
|---|---------|-------------|
| 01 | [Quickstart](01_quickstart.py) | Goal hijacking detection, tool schema validation, agent scan |
| 02 | [ASI-01 to ASI-05](02_asi01_to_asi05.py) | Goal hijack, tool misuse, identity, supply chain, code execution |
| 03 | [ASI-06 to ASI-10](03_asi06_to_asi10.py) | Memory poisoning, inter-agent trust, circuit breaker, drift |
| 04 | [OWASP Guard Middleware](04_owasp_guard_middleware.py) | Unified OWASP guard pipeline for all agent calls |
| 05 | [Agent Scanner](05_agent_scanner.py) | Scan agent configs and generate graded security reports |
| 06 | [Drift Detection](06_drift_detection.py) | Establish baselines and detect rogue agent metric drift |
| 07 | [LangChain OWASP](07_langchain_owasp.py) | Wrap LangChain tool calls with OWASP guard middleware |

## Running the examples

```bash
pip install aumos-owasp-defenses
python examples/01_quickstart.py
```

For framework integrations:

```bash
pip install langchain   # for example 07
```
