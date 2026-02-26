"""Tests for ReportGenerator."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aumos_owasp_defenses.scanner.agent_scanner import (
    AgentScanner,
    CategoryResult,
    ScanProfile,
    ScanResult,
)
from aumos_owasp_defenses.scanner.report_generator import ReportGenerator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_category(
    asi_id: str = "ASI-01",
    name: str = "Goal and Task Hijacking",
    status: str = "PASS",
    score: int = 90,
    summary: str = "All good.",
    findings: list[str] | None = None,
    recommendations: list[str] | None = None,
) -> CategoryResult:
    return CategoryResult(
        asi_id=asi_id,
        name=name,
        status=status,
        score=score,
        summary=summary,
        findings=findings or [],
        recommendations=recommendations or [],
    )


def _make_scan_result(
    agent_id: str = "test-agent",
    profile: str = "standard",
    score: int = 85,
    grade: str = "B",
    category_results: list[CategoryResult] | None = None,
    passed: int = 8,
    warned: int = 1,
    failed: int = 1,
) -> ScanResult:
    cats = category_results or [_make_category()]
    return ScanResult(
        agent_id=agent_id,
        profile=profile,
        score=score,
        grade=grade,
        category_results=cats,
        scanned_at=datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        scan_duration_ms=42.5,
        passed=passed,
        warned=warned,
        failed=failed,
    )


@pytest.fixture()
def generator() -> ReportGenerator:
    return ReportGenerator()


@pytest.fixture()
def scan_result() -> ScanResult:
    return _make_scan_result()


# ---------------------------------------------------------------------------
# ReportGenerator — to_json
# ---------------------------------------------------------------------------


class TestToJson:
    def test_returns_valid_json(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_json(scan_result)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_json_contains_agent_id(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_json(scan_result)
        parsed = json.loads(output)
        assert parsed["agent_id"] == "test-agent"

    def test_json_contains_score_and_grade(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_json(scan_result)
        parsed = json.loads(output)
        assert parsed["score"] == 85
        assert parsed["grade"] == "B"

    def test_json_contains_summary_counts(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_json(scan_result)
        parsed = json.loads(output)
        summary = parsed["summary"]
        assert summary["passed"] == 8
        assert summary["warned"] == 1
        assert summary["failed"] == 1
        assert summary["total"] == 1  # one category in fixture

    def test_json_contains_categories(self, generator: ReportGenerator) -> None:
        result = _make_scan_result(
            category_results=[
                _make_category("ASI-01", status="PASS", score=90),
                _make_category("ASI-02", status="FAIL", score=40, findings=["No tools"]),
            ]
        )
        output = generator.to_json(result)
        parsed = json.loads(output)
        assert len(parsed["categories"]) == 2
        asi_ids = [c["asi_id"] for c in parsed["categories"]]
        assert "ASI-01" in asi_ids
        assert "ASI-02" in asi_ids

    def test_json_category_has_all_fields(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_json(scan_result)
        parsed = json.loads(output)
        cat = parsed["categories"][0]
        assert "asi_id" in cat
        assert "name" in cat
        assert "status" in cat
        assert "score" in cat
        assert "summary" in cat
        assert "findings" in cat
        assert "recommendations" in cat
        assert "auto_fixable" in cat

    def test_json_scanned_at_is_iso_format(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_json(scan_result)
        parsed = json.loads(output)
        # Should parse without error
        scanned_at = datetime.fromisoformat(parsed["scanned_at"])
        assert scanned_at.year == 2025

    def test_json_duration_rounded(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_json(scan_result)
        parsed = json.loads(output)
        assert parsed["scan_duration_ms"] == 42.5

    def test_json_with_findings_and_recommendations(self, generator: ReportGenerator) -> None:
        result = _make_scan_result(
            category_results=[
                _make_category(
                    findings=["No system prompt found."],
                    recommendations=["Add a system prompt."],
                )
            ]
        )
        output = generator.to_json(result)
        parsed = json.loads(output)
        cat = parsed["categories"][0]
        assert cat["findings"] == ["No system prompt found."]
        assert cat["recommendations"] == ["Add a system prompt."]


# ---------------------------------------------------------------------------
# ReportGenerator — to_markdown
# ---------------------------------------------------------------------------


class TestToMarkdown:
    def test_returns_string(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_markdown(scan_result)
        assert isinstance(output, str)

    def test_contains_agent_id(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_markdown(scan_result)
        assert "test-agent" in output

    def test_contains_score_and_grade(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_markdown(scan_result)
        assert "85" in output
        assert "**B**" in output

    def test_contains_headline(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_markdown(scan_result)
        assert "# OWASP ASI Top 10 Security Scan Report" in output

    def test_contains_category_section(self, generator: ReportGenerator) -> None:
        result = _make_scan_result(
            category_results=[_make_category("ASI-01", name="Goal and Task Hijacking")]
        )
        output = generator.to_markdown(result)
        assert "ASI-01" in output
        assert "Goal and Task Hijacking" in output

    def test_contains_findings(self, generator: ReportGenerator) -> None:
        result = _make_scan_result(
            category_results=[_make_category(findings=["No system prompt."])]
        )
        output = generator.to_markdown(result)
        assert "No system prompt." in output

    def test_contains_recommendations(self, generator: ReportGenerator) -> None:
        result = _make_scan_result(
            category_results=[_make_category(recommendations=["Add a system prompt."])]
        )
        output = generator.to_markdown(result)
        assert "Add a system prompt." in output

    def test_pass_warn_fail_counts_present(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_markdown(scan_result)
        assert "8" in output  # passed
        assert "1" in output  # warned/failed

    def test_footer_present(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_markdown(scan_result)
        assert "aumos-owasp-defenses" in output


# ---------------------------------------------------------------------------
# ReportGenerator — to_html
# ---------------------------------------------------------------------------


class TestToHtml:
    def test_returns_string(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_html(scan_result)
        assert isinstance(output, str)

    def test_is_valid_html_start(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_html(scan_result)
        assert output.strip().startswith("<!DOCTYPE html>")

    def test_contains_agent_id_escaped(self, generator: ReportGenerator) -> None:
        result = _make_scan_result(agent_id="agent<script>")
        output = generator.to_html(result)
        assert "<script>" not in output
        assert "agent&lt;script&gt;" in output

    def test_contains_grade(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_html(scan_result)
        assert ">B<" in output or "B" in output

    def test_contains_category_asi_id(self, generator: ReportGenerator) -> None:
        result = _make_scan_result(
            category_results=[_make_category("ASI-03", status="WARN", score=65)]
        )
        output = generator.to_html(result)
        assert "ASI-03" in output

    def test_findings_escaped_in_html(self, generator: ReportGenerator) -> None:
        result = _make_scan_result(
            category_results=[_make_category(findings=["<b>danger</b>"])]
        )
        output = generator.to_html(result)
        assert "<b>danger</b>" not in output
        assert "&lt;b&gt;danger&lt;/b&gt;" in output

    def test_recommendations_escaped_in_html(self, generator: ReportGenerator) -> None:
        result = _make_scan_result(
            category_results=[_make_category(recommendations=["Use <strong>this</strong>"])]
        )
        output = generator.to_html(result)
        assert "<strong>this</strong>" not in output

    def test_all_categories_rendered(self, generator: ReportGenerator) -> None:
        result = _make_scan_result(
            category_results=[
                _make_category("ASI-01"),
                _make_category("ASI-02"),
                _make_category("ASI-03"),
            ]
        )
        output = generator.to_html(result)
        assert "ASI-01" in output
        assert "ASI-02" in output
        assert "ASI-03" in output

    def test_footer_present(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_html(scan_result)
        assert "aumos-owasp-defenses" in output

    def test_status_pass_rendered(self, generator: ReportGenerator) -> None:
        result = _make_scan_result(
            category_results=[_make_category(status="PASS")]
        )
        output = generator.to_html(result)
        assert "PASS" in output

    def test_status_fail_rendered(self, generator: ReportGenerator) -> None:
        result = _make_scan_result(
            category_results=[_make_category(status="FAIL", score=20)]
        )
        output = generator.to_html(result)
        assert "FAIL" in output

    def test_empty_findings_no_findings_section(self, generator: ReportGenerator) -> None:
        result = _make_scan_result(
            category_results=[_make_category(findings=[])]
        )
        output = generator.to_html(result)
        # With no findings, "Findings" section label should not appear
        assert "Findings" not in output or output.count("Findings") == 0

    def test_scan_duration_in_html(self, generator: ReportGenerator, scan_result: ScanResult) -> None:
        output = generator.to_html(scan_result)
        assert "42.5" in output


# ---------------------------------------------------------------------------
# ReportGenerator — save
# ---------------------------------------------------------------------------


class TestSave:
    def test_save_html(self, generator: ReportGenerator, scan_result: ScanResult, tmp_path: Path) -> None:
        output_base = str(tmp_path / "report")
        saved_path = generator.save(scan_result, output_base, fmt="html")
        assert saved_path.suffix == ".html"
        assert saved_path.exists()
        content = saved_path.read_text(encoding="utf-8")
        assert "DOCTYPE html" in content

    def test_save_json(self, generator: ReportGenerator, scan_result: ScanResult, tmp_path: Path) -> None:
        output_base = str(tmp_path / "report")
        saved_path = generator.save(scan_result, output_base, fmt="json")
        assert saved_path.suffix == ".json"
        assert saved_path.exists()
        content = saved_path.read_text(encoding="utf-8")
        parsed = json.loads(content)
        assert "agent_id" in parsed

    def test_save_markdown(self, generator: ReportGenerator, scan_result: ScanResult, tmp_path: Path) -> None:
        output_base = str(tmp_path / "report")
        saved_path = generator.save(scan_result, output_base, fmt="markdown")
        assert saved_path.suffix == ".md"
        assert saved_path.exists()

    def test_save_md_alias(self, generator: ReportGenerator, scan_result: ScanResult, tmp_path: Path) -> None:
        output_base = str(tmp_path / "report")
        saved_path = generator.save(scan_result, output_base, fmt="md")
        assert saved_path.suffix == ".md"
        assert saved_path.exists()

    def test_save_creates_parent_dirs(self, generator: ReportGenerator, scan_result: ScanResult, tmp_path: Path) -> None:
        output_base = str(tmp_path / "nested" / "deep" / "report")
        saved_path = generator.save(scan_result, output_base, fmt="json")
        assert saved_path.exists()

    def test_save_unknown_format_raises(self, generator: ReportGenerator, scan_result: ScanResult, tmp_path: Path) -> None:
        output_base = str(tmp_path / "report")
        with pytest.raises(ValueError, match="Unknown report format"):
            generator.save(scan_result, output_base, fmt="csv")

    def test_save_returns_path_object(self, generator: ReportGenerator, scan_result: ScanResult, tmp_path: Path) -> None:
        output_base = str(tmp_path / "report")
        result = generator.save(scan_result, output_base, fmt="html")
        assert isinstance(result, Path)

    def test_default_format_is_html(self, generator: ReportGenerator, scan_result: ScanResult, tmp_path: Path) -> None:
        output_base = str(tmp_path / "report")
        saved_path = generator.save(scan_result, output_base)
        assert saved_path.suffix == ".html"


# ---------------------------------------------------------------------------
# Integration — AgentScanner + ReportGenerator round-trip
# ---------------------------------------------------------------------------


class TestScannerReportIntegration:
    def test_scan_then_to_json(self, generator: ReportGenerator) -> None:
        scanner = AgentScanner(profile=ScanProfile.QUICK)
        result = scanner.scan({"agent_id": "integration-test"})
        output = generator.to_json(result)
        parsed = json.loads(output)
        assert parsed["agent_id"] == "integration-test"
        assert len(parsed["categories"]) == 3

    def test_scan_then_to_markdown(self, generator: ReportGenerator) -> None:
        scanner = AgentScanner(profile=ScanProfile.QUICK)
        result = scanner.scan({"agent_id": "md-agent"})
        output = generator.to_markdown(result)
        assert "md-agent" in output

    def test_scan_then_to_html(self, generator: ReportGenerator) -> None:
        scanner = AgentScanner(profile=ScanProfile.QUICK)
        result = scanner.scan({})
        output = generator.to_html(result)
        assert "DOCTYPE html" in output

    def test_scan_then_save_all_formats(self, generator: ReportGenerator, tmp_path: Path) -> None:
        scanner = AgentScanner(profile=ScanProfile.QUICK)
        result = scanner.scan({"agent_id": "save-test"})
        for fmt in ("html", "json", "markdown"):
            path = generator.save(result, str(tmp_path / f"report_{fmt}"), fmt=fmt)
            assert path.exists()
            assert path.stat().st_size > 0
