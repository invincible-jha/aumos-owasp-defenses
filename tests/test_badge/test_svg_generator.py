"""Tests for aumos_owasp_defenses.badge.svg_generator."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aumos_owasp_defenses.badge.scanner_integration import (
    BadgeScanReport,
    OWASPBadgeScanner,
    ScanResult,
)
from aumos_owasp_defenses.badge.svg_generator import (
    SVGBadgeGenerator,
    _escape_xml,
    _text_width,
    is_valid_svg,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_report(level: str, score: float = 0.5) -> BadgeScanReport:
    """Build a minimal BadgeScanReport with the given level and score."""
    dummy_result = ScanResult(
        category="ASI-01",
        status="partial",
        defenses_found=(),
        recommendations=(),
    )
    return BadgeScanReport(
        scan_id="test-scan-id-1234",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        results=(dummy_result,),
        overall_level=level,
        score=score,
    )


@pytest.fixture()
def generator() -> SVGBadgeGenerator:
    return SVGBadgeGenerator()


@pytest.fixture()
def gold_report() -> BadgeScanReport:
    return _make_report("gold", 0.95)


@pytest.fixture()
def silver_report() -> BadgeScanReport:
    return _make_report("silver", 0.75)


@pytest.fixture()
def bronze_report() -> BadgeScanReport:
    return _make_report("bronze", 0.55)


@pytest.fixture()
def none_report() -> BadgeScanReport:
    return _make_report("none", 0.1)


# ---------------------------------------------------------------------------
# Tests: helper functions
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_is_valid_svg_true_for_valid_svg(self) -> None:
        svg = '<svg xmlns="http://www.w3.org/2000/svg"></svg>'
        assert is_valid_svg(svg) is True

    def test_is_valid_svg_false_for_missing_closing_tag(self) -> None:
        assert is_valid_svg("<svg>no close") is False

    def test_is_valid_svg_false_for_empty_string(self) -> None:
        assert is_valid_svg("") is False

    def test_is_valid_svg_whitespace_tolerant(self) -> None:
        svg = "  <svg></svg>  "
        assert is_valid_svg(svg) is True

    def test_escape_xml_ampersand(self) -> None:
        assert "&amp;" in _escape_xml("A & B")

    def test_escape_xml_less_than(self) -> None:
        assert "&lt;" in _escape_xml("a < b")

    def test_escape_xml_greater_than(self) -> None:
        assert "&gt;" in _escape_xml("a > b")

    def test_escape_xml_double_quote(self) -> None:
        assert "&quot;" in _escape_xml('say "hi"')

    def test_escape_xml_single_quote(self) -> None:
        assert "&#x27;" in _escape_xml("it's")

    def test_escape_xml_no_change_for_plain_text(self) -> None:
        assert _escape_xml("hello world") == "hello world"

    def test_text_width_positive(self) -> None:
        assert _text_width("OWASP ASI") > 0

    def test_text_width_proportional_to_length(self) -> None:
        short = _text_width("Hi")
        long = _text_width("Hello World")
        assert long > short

    def test_text_width_includes_padding(self) -> None:
        # Even empty string should have padding
        assert _text_width("") >= 20  # 2 * 10 padding


# ---------------------------------------------------------------------------
# Tests: SVGBadgeGenerator.generate
# ---------------------------------------------------------------------------


class TestSVGBadgeGeneratorGenerate:
    def test_generate_returns_string(self, generator: SVGBadgeGenerator, gold_report: BadgeScanReport) -> None:
        svg = generator.generate(gold_report)
        assert isinstance(svg, str)

    def test_generate_starts_with_svg_tag(self, generator: SVGBadgeGenerator, gold_report: BadgeScanReport) -> None:
        svg = generator.generate(gold_report)
        assert svg.strip().startswith("<svg")

    def test_generate_ends_with_closing_svg_tag(self, generator: SVGBadgeGenerator, gold_report: BadgeScanReport) -> None:
        svg = generator.generate(gold_report)
        assert svg.strip().endswith("</svg>")

    def test_generate_is_valid_svg(self, generator: SVGBadgeGenerator, gold_report: BadgeScanReport) -> None:
        assert is_valid_svg(generator.generate(gold_report))

    def test_generate_contains_label(self, generator: SVGBadgeGenerator, gold_report: BadgeScanReport) -> None:
        svg = generator.generate(gold_report)
        assert "OWASP ASI" in svg

    def test_generate_gold_contains_gold_text(self, generator: SVGBadgeGenerator, gold_report: BadgeScanReport) -> None:
        svg = generator.generate(gold_report)
        assert "Gold" in svg

    def test_generate_silver_contains_silver_text(self, generator: SVGBadgeGenerator, silver_report: BadgeScanReport) -> None:
        svg = generator.generate(silver_report)
        assert "Silver" in svg

    def test_generate_bronze_contains_bronze_text(self, generator: SVGBadgeGenerator, bronze_report: BadgeScanReport) -> None:
        svg = generator.generate(bronze_report)
        assert "Bronze" in svg

    def test_generate_none_contains_none_text(self, generator: SVGBadgeGenerator, none_report: BadgeScanReport) -> None:
        svg = generator.generate(none_report)
        assert "None" in svg

    def test_gold_badge_uses_gold_color(self, generator: SVGBadgeGenerator, gold_report: BadgeScanReport) -> None:
        svg = generator.generate(gold_report)
        # Color without # prefix
        assert "ffd700" in svg

    def test_silver_badge_uses_silver_color(self, generator: SVGBadgeGenerator, silver_report: BadgeScanReport) -> None:
        svg = generator.generate(silver_report)
        assert "c0c0c0" in svg

    def test_bronze_badge_uses_bronze_color(self, generator: SVGBadgeGenerator, bronze_report: BadgeScanReport) -> None:
        svg = generator.generate(bronze_report)
        assert "cd7f32" in svg

    def test_none_badge_uses_red_color(self, generator: SVGBadgeGenerator, none_report: BadgeScanReport) -> None:
        svg = generator.generate(none_report)
        assert "e05d44" in svg

    def test_generate_contains_xmlns(self, generator: SVGBadgeGenerator, gold_report: BadgeScanReport) -> None:
        svg = generator.generate(gold_report)
        assert 'xmlns="http://www.w3.org/2000/svg"' in svg

    def test_generate_contains_clip_path(self, generator: SVGBadgeGenerator, gold_report: BadgeScanReport) -> None:
        svg = generator.generate(gold_report)
        assert "clipPath" in svg

    def test_generate_height_20(self, generator: SVGBadgeGenerator, gold_report: BadgeScanReport) -> None:
        svg = generator.generate(gold_report)
        assert 'height="20"' in svg

    def test_generate_contains_linear_gradient(self, generator: SVGBadgeGenerator, gold_report: BadgeScanReport) -> None:
        svg = generator.generate(gold_report)
        assert "linearGradient" in svg

    def test_colors_class_var_has_all_levels(self, generator: SVGBadgeGenerator) -> None:
        assert "gold" in SVGBadgeGenerator.COLORS
        assert "silver" in SVGBadgeGenerator.COLORS
        assert "bronze" in SVGBadgeGenerator.COLORS
        assert "none" in SVGBadgeGenerator.COLORS


# ---------------------------------------------------------------------------
# Tests: SVGBadgeGenerator.generate_with_score
# ---------------------------------------------------------------------------


class TestGenerateWithScore:
    def test_generate_with_score_contains_percentage(self, generator: SVGBadgeGenerator, gold_report: BadgeScanReport) -> None:
        svg = generator.generate_with_score(gold_report)
        assert "%" in svg

    def test_generate_with_score_contains_level(self, generator: SVGBadgeGenerator, silver_report: BadgeScanReport) -> None:
        svg = generator.generate_with_score(silver_report)
        assert "Silver" in svg

    def test_generate_with_score_is_valid_svg(self, generator: SVGBadgeGenerator, bronze_report: BadgeScanReport) -> None:
        assert is_valid_svg(generator.generate_with_score(bronze_report))


# ---------------------------------------------------------------------------
# Integration: scan → generate
# ---------------------------------------------------------------------------


class TestScanToSVGIntegration:
    def test_full_pipeline_produces_valid_svg(self) -> None:
        scanner = OWASPBadgeScanner()
        generator = SVGBadgeGenerator()

        config = {
            "agent_id": "demo",
            "system_prompt": "You are a helpful assistant that validates inputs.",
        }
        report = scanner.scan(config)
        svg = generator.generate(report)

        assert is_valid_svg(svg)
        assert "OWASP ASI" in svg

    def test_custom_label(self) -> None:
        gen = SVGBadgeGenerator(label="My Agent")
        report = _make_report("gold")
        svg = gen.generate(report)
        assert "My Agent" in svg

    def test_generate_and_generate_with_score_differ(self) -> None:
        gen = SVGBadgeGenerator()
        report = _make_report("silver", 0.75)
        plain = gen.generate(report)
        scored = gen.generate_with_score(report)
        # The scored version should have a percentage in the right-panel message
        assert "%" in scored
        # The two variants must produce different SVG output — the scored version
        # includes the numeric percentage in its message text, making it wider.
        assert plain != scored
