"""CLI entry point for aumos-owasp-defenses.

Invoked as::

    aumos-owasp [OPTIONS] COMMAND [ARGS]...

or, during development::

    python -m aumos_owasp_defenses.cli.main

Commands
--------
scan AGENT_PATH
    Run all (or selected) ASI defense checks against an agent config file.
check TEXT
    Quick check of a text snippet for boundary violations (ASI-01).
patterns list
    List all ASI-01 boundary-detection patterns.
version
    Show detailed version information.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


@click.group()
@click.version_option(package_name="aumos-owasp-defenses")
def cli() -> None:
    """OWASP Agentic Security Initiative (ASI) Top 10 defensive toolkit."""


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


@cli.command(name="version")
def version_command() -> None:
    """Show detailed version and environment information."""
    from aumos_owasp_defenses import __version__
    import platform

    console.print(f"[bold cyan]aumos-owasp-defenses[/bold cyan] v{__version__}")
    console.print(f"Python {platform.python_version()} on {platform.system()}")
    console.print("OWASP Agentic Security Initiative (ASI) Top 10 Defensive Library")


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@cli.command(name="scan")
@click.argument("agent_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--profile",
    type=click.Choice(["standard", "quick", "mcp_focused", "compliance"]),
    default="standard",
    show_default=True,
    help="Scan profile controlling which ASI categories are evaluated.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["html", "json", "markdown"]),
    default="html",
    show_default=True,
    help="Output report format.",
)
@click.option(
    "--output",
    "-o",
    default="scan_report",
    show_default=True,
    help="Output file path (without extension).",
)
@click.option(
    "--ci",
    is_flag=True,
    default=False,
    help="CI mode: exit with non-zero code when score is below threshold.",
)
@click.option(
    "--threshold",
    default=70,
    show_default=True,
    type=int,
    help="Minimum passing score for CI mode (0-100).",
)
def scan_command(
    agent_path: Path,
    profile: str,
    output_format: str,
    output: str,
    ci: bool,
    threshold: int,
) -> None:
    """Scan an agent configuration file for ASI security issues.

    AGENT_PATH may be a JSON or YAML file containing the agent config dict.

    Example::

        aumos-owasp scan my_agent.yaml --profile standard --format html -o report
    """
    from aumos_owasp_defenses.scanner import AgentScanner, ReportGenerator

    # --- Load agent config ---
    try:
        raw = agent_path.read_text(encoding="utf-8")
    except OSError as exc:
        console.print(f"[red]Error reading {agent_path}: {exc}[/red]")
        sys.exit(1)

    agent_config: dict[str, object]
    try:
        if agent_path.suffix.lower() in (".yaml", ".yml"):
            loaded = yaml.safe_load(raw)
            agent_config = loaded if isinstance(loaded, dict) else {}
        else:
            loaded = json.loads(raw)
            agent_config = loaded if isinstance(loaded, dict) else {}
    except Exception as exc:
        console.print(f"[red]Error parsing {agent_path}: {exc}[/red]")
        sys.exit(1)

    # --- Run scan ---
    scanner = AgentScanner(profile=profile)
    with console.status("[bold green]Scanning agent configuration..."):
        result = scanner.scan(agent_config)

    # --- Console summary ---
    grade_colour = {
        "A": "green", "B": "green", "C": "yellow",
        "D": "orange3", "F": "red",
    }.get(result.grade, "white")

    console.print()
    console.print(
        f"[bold]Agent:[/bold] {result.agent_id}  "
        f"[bold]Profile:[/bold] {result.profile}  "
        f"[bold]Duration:[/bold] {result.scan_duration_ms:.1f}ms"
    )
    console.print(
        f"[bold]Score:[/bold] {result.score}/100  "
        f"[bold]Grade:[/bold] [{grade_colour}]{result.grade}[/{grade_colour}]  "
        f"PASS:{result.passed} WARN:{result.warned} FAIL:{result.failed}"
    )
    console.print()

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("ASI ID", style="bold", width=8)
    table.add_column("Category", min_width=30)
    table.add_column("Status", width=8)
    table.add_column("Score", width=7, justify="right")
    table.add_column("Summary", min_width=35)

    status_styles = {"PASS": "green", "WARN": "yellow", "FAIL": "red"}
    for cat in result.category_results:
        style = status_styles.get(cat.status, "white")
        table.add_row(
            cat.asi_id,
            cat.name,
            f"[{style}]{cat.status}[/{style}]",
            str(cat.score),
            cat.summary[:60],
        )

    console.print(table)

    # --- Generate report ---
    generator = ReportGenerator()
    report_path = generator.save(result, output, fmt=output_format)
    console.print(f"\n[bold]Report written to:[/bold] {report_path}")

    # --- CI exit code ---
    if ci and result.score < threshold:
        console.print(
            f"[red]CI check FAILED: score {result.score} is below threshold {threshold}.[/red]"
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


@cli.command(name="check")
@click.argument("text")
@click.option(
    "--threshold",
    type=click.Choice(["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="MEDIUM",
    show_default=True,
    help="Minimum threat level to flag as a violation.",
)
def check_command(text: str, threshold: str) -> None:
    """Quick check of TEXT for instruction-data boundary violations (ASI-01).

    Example::

        aumos-owasp check "Summarise the attached document."
    """
    from aumos_owasp_defenses.defenses.asi01_goal_hijack import (
        BoundaryDetector,
        ThreatLevel,
    )

    level_map: dict[str, ThreatLevel] = {
        "NONE": ThreatLevel.NONE,
        "LOW": ThreatLevel.LOW,
        "MEDIUM": ThreatLevel.MEDIUM,
        "HIGH": ThreatLevel.HIGH,
        "CRITICAL": ThreatLevel.CRITICAL,
    }
    threat_level = level_map[threshold]
    detector = BoundaryDetector(threshold=threat_level)
    result = detector.analyze(text)

    if result.is_safe:
        console.print(f"[green]SAFE[/green] — no patterns at or above {threshold} detected.")
        console.print(f"  Analysis: {result.analysis_ms:.2f}ms, {result.input_length} chars")
    else:
        console.print(
            f"[red]UNSAFE[/red] — threat level: {result.threat_level.name}, "
            f"{len(result.findings)} finding(s)"
        )
        for finding in result.findings:
            colour = "red" if finding.threat_level >= ThreatLevel.HIGH else "yellow"
            console.print(
                f"  [{colour}][{finding.threat_level.name}][/{colour}] "
                f"{finding.pattern_name} at offset {finding.location}"
            )
            console.print(f"    {finding.recommendation}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# patterns
# ---------------------------------------------------------------------------


@cli.group(name="patterns")
def patterns_group() -> None:
    """Commands for inspecting detection patterns."""


@patterns_group.command(name="list")
@click.option(
    "--min-level",
    type=click.Choice(["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="NONE",
    show_default=True,
    help="Only show patterns at or above this threat level.",
)
def patterns_list_command(min_level: str) -> None:
    """List all ASI-01 boundary-detection patterns.

    Example::

        aumos-owasp patterns list --min-level HIGH
    """
    from aumos_owasp_defenses.defenses.asi01_goal_hijack import BoundaryDetector, ThreatLevel

    level_map: dict[str, int] = {
        "NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
    }
    min_level_value = level_map[min_level]

    detector = BoundaryDetector()
    patterns = [
        p for p in detector.list_patterns()
        if level_map.get(p["threat_level"], 0) >= min_level_value
    ]

    console.print(f"\n[bold]ASI-01 Detection Patterns[/bold] ({len(patterns)} shown)\n")

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Pattern Name", min_width=35)
    table.add_column("Threat Level", width=14)
    table.add_column("Recommendation", min_width=40)

    level_colours: dict[str, str] = {
        "CRITICAL": "red", "HIGH": "orange3",
        "MEDIUM": "yellow", "LOW": "blue", "NONE": "white",
    }
    for pattern in patterns:
        level = str(pattern["threat_level"])
        colour = level_colours.get(level, "white")
        table.add_row(
            str(pattern["name"]),
            f"[{colour}]{level}[/{colour}]",
            str(pattern["recommendation"])[:70],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# plugins (from scaffold)
# ---------------------------------------------------------------------------


@cli.command(name="plugins")
def plugins_command() -> None:
    """List all registered plugins loaded from entry-points."""
    console.print("[bold]Registered plugins:[/bold]")
    console.print("  (No plugins registered. Install a plugin package to see entries here.)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    cli()
