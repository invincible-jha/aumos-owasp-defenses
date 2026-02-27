"""Convenience API for aumos-owasp-defenses — 3-line quickstart.

Example
-------
::

    from aumos_owasp_defenses import OWASPDefenses
    defenses = OWASPDefenses()
    result = defenses.scan({"agent_id": "demo", "system_prompt": "You are a helper."})

"""
from __future__ import annotations

from typing import Any


class OWASPDefenses:
    """Zero-config OWASP ASI Top 10 defense suite for the 80% use case.

    Wraps AgentScanner with default settings so all 10 OWASP categories
    are checked with a single method call.

    Example
    -------
    ::

        from aumos_owasp_defenses import OWASPDefenses
        defenses = OWASPDefenses()
        result = defenses.scan({"agent_id": "my-agent", "system_prompt": "Help users."})
        print(result.grade)   # "A" through "F"
        print(result.passed)  # True if no critical findings
    """

    def __init__(self) -> None:
        from aumos_owasp_defenses.scanner.agent_scanner import AgentScanner

        self._scanner = AgentScanner()

    def scan(self, agent_config: dict[str, Any]) -> Any:
        """Run all OWASP ASI Top 10 checks on an agent configuration.

        Parameters
        ----------
        agent_config:
            Agent configuration dict. Common keys include ``agent_id``,
            ``system_prompt``, ``tools``, and ``data_sources``.

        Returns
        -------
        ScanResult
            Result with ``.grade`` (A–F), ``.passed`` bool, and
            ``.category_results`` per-category breakdown.

        Example
        -------
        ::

            defenses = OWASPDefenses()
            result = defenses.scan({
                "agent_id": "assistant",
                "system_prompt": "You are a helpful assistant.",
            })
            print(result.grade)
        """
        return self._scanner.scan(agent_config)

    def check_input(self, text: str) -> bool:
        """Quick check whether text is safe from goal-hijacking (ASI-01).

        Parameters
        ----------
        text:
            Text to check for instruction-data boundary violations.

        Returns
        -------
        bool
            True if text appears safe, False if a boundary violation is found.
        """
        from aumos_owasp_defenses.defenses.asi01_goal_hijack import check_safe

        return check_safe(text)

    @property
    def scanner(self) -> Any:
        """The underlying AgentScanner instance."""
        return self._scanner

    def __repr__(self) -> str:
        return "OWASPDefenses(scanner=AgentScanner)"
