"""Test that the 3-line quickstart API works for aumos-owasp-defenses."""
from __future__ import annotations


def test_quickstart_import() -> None:
    from aumos_owasp_defenses import OWASPDefenses

    defenses = OWASPDefenses()
    assert defenses is not None


def test_quickstart_scan() -> None:
    from aumos_owasp_defenses import OWASPDefenses

    defenses = OWASPDefenses()
    result = defenses.scan({"agent_id": "demo", "system_prompt": "You are a helper."})
    assert result is not None


def test_quickstart_scan_has_grade() -> None:
    from aumos_owasp_defenses import OWASPDefenses

    defenses = OWASPDefenses()
    result = defenses.scan({"agent_id": "demo", "system_prompt": "Help users safely."})
    assert result.grade in ("A", "B", "C", "D", "F")


def test_quickstart_check_input_safe() -> None:
    from aumos_owasp_defenses import OWASPDefenses

    defenses = OWASPDefenses()
    is_safe = defenses.check_input("Summarise the report below.")
    assert isinstance(is_safe, bool)
    assert is_safe is True


def test_quickstart_scanner_accessible() -> None:
    from aumos_owasp_defenses import OWASPDefenses
    from aumos_owasp_defenses.scanner.agent_scanner import AgentScanner

    defenses = OWASPDefenses()
    assert isinstance(defenses.scanner, AgentScanner)


def test_quickstart_repr() -> None:
    from aumos_owasp_defenses import OWASPDefenses

    defenses = OWASPDefenses()
    assert "OWASPDefenses" in repr(defenses)
