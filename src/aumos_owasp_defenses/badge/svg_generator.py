"""SVG badge generator for OWASP ASI badge scan reports.

Generates shields.io-style flat SVG badges from a :class:`BadgeScanReport`.
The badge has a dark-grey left panel labelled ``"OWASP ASI"`` and a
colour-coded right panel showing the overall compliance level
(``"Gold"``, ``"Silver"``, ``"Bronze"``, or ``"None"``).

The colours follow conventional badge semantics:

- Gold   → #ffd700 (gold / yellow)
- Silver → #c0c0c0 (silver / grey)
- Bronze → #cd7f32 (bronze / brown)
- None   → #e05d44 (red — shields.io "failing" colour)

Usage
-----
>>> from aumos_owasp_defenses.badge.scanner_integration import OWASPBadgeScanner
>>> from aumos_owasp_defenses.badge.svg_generator import SVGBadgeGenerator
>>> scanner = OWASPBadgeScanner()
>>> report = scanner.scan({"agent_id": "demo", "system_prompt": "Be helpful."})
>>> gen = SVGBadgeGenerator()
>>> svg = gen.generate(report)
>>> svg.startswith("<svg")
True
"""
from __future__ import annotations

from typing import ClassVar

from aumos_owasp_defenses.badge.scanner_integration import BadgeScanReport


# ---------------------------------------------------------------------------
# SVG template
# ---------------------------------------------------------------------------

# Flat shields.io-style badge template.
# Template variables:
#   {label}             — left panel text  (e.g. "OWASP ASI")
#   {message}           — right panel text (e.g. "Gold")
#   {color}             — right panel fill hex colour, WITHOUT leading #
#   {label_width}       — pixel width of the left panel
#   {msg_width}         — pixel width of the right panel
#   {total_width}       — label_width + msg_width
#   {label_mid}         — x-midpoint of label panel × 10  (SVG scaled coords)
#   {msg_mid}           — x-midpoint of message panel × 10
#   {label_text_length} — textLength for label (scaled coords)
#   {msg_text_length}   — textLength for message (scaled coords)
_SVG_TEMPLATE: str = """\
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" \
width="{total_width}" height="20" role="img" aria-label="{label}: {message}">
  <title>{label}: {message}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{msg_width}" height="20" fill="#{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" \
font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110">
    <text x="{label_mid}" y="150" fill="#010101" fill-opacity=".3" \
transform="scale(.1)" textLength="{label_text_length}" lengthAdjust="spacing">{label}</text>
    <text x="{label_mid}" y="140" transform="scale(.1)" \
textLength="{label_text_length}" lengthAdjust="spacing">{label}</text>
    <text x="{msg_mid}" y="150" fill="#010101" fill-opacity=".3" \
transform="scale(.1)" textLength="{msg_text_length}" lengthAdjust="spacing">{message}</text>
    <text x="{msg_mid}" y="140" transform="scale(.1)" \
textLength="{msg_text_length}" lengthAdjust="spacing">{message}</text>
  </g>
</svg>"""

#: Left panel label text shown on every badge.
_BADGE_LABEL: str = "OWASP ASI"

#: Approximate pixel width per character at the badge font size (DejaVu Sans 11).
_CHARS_PER_PX: float = 6.5

#: Fixed horizontal padding (px) added on each side of each panel's text.
_PANEL_PADDING: int = 10

#: Display label for each overall_level value.
_LEVEL_DISPLAY_NAMES: dict[str, str] = {
    "gold": "Gold",
    "silver": "Silver",
    "bronze": "Bronze",
    "none": "None",
}


# ---------------------------------------------------------------------------
# SVGBadgeGenerator
# ---------------------------------------------------------------------------


class SVGBadgeGenerator:
    """Generate shields.io-style SVG badges from a :class:`BadgeScanReport`.

    The generator is stateless and safe for concurrent use.

    Parameters
    ----------
    label:
        Left-panel text displayed on every badge.
        Defaults to ``"OWASP ASI"``.

    Example
    -------
    >>> gen = SVGBadgeGenerator()
    >>> from aumos_owasp_defenses.badge.scanner_integration import OWASPBadgeScanner
    >>> report = OWASPBadgeScanner().scan({"agent_id": "x"})
    >>> svg = gen.generate(report)
    >>> "<svg" in svg and "</svg>" in svg
    True
    """

    COLORS: ClassVar[dict[str, str]] = {
        "gold": "#ffd700",
        "silver": "#c0c0c0",
        "bronze": "#cd7f32",
        "none": "#e05d44",
    }

    def __init__(self, label: str = _BADGE_LABEL) -> None:
        self._label = label

    def generate(self, report: BadgeScanReport) -> str:
        """Generate a complete SVG badge string from *report*.

        Parameters
        ----------
        report:
            The :class:`BadgeScanReport` produced by
            :class:`~aumos_owasp_defenses.badge.scanner_integration.OWASPBadgeScanner`.

        Returns
        -------
        str
            A complete SVG 1.1 document as a string.
        """
        level = report.overall_level
        message = _LEVEL_DISPLAY_NAMES.get(level, level.title())
        color = self.COLORS.get(level, self.COLORS["none"]).lstrip("#")
        return self._render_svg(
            label=self._label,
            message=message,
            color=color,
        )

    def generate_with_score(self, report: BadgeScanReport) -> str:
        """Generate a badge that also shows the numeric compliance score.

        The right panel shows the level and the percentage score, e.g.
        ``"Gold 92%"``.

        Parameters
        ----------
        report:
            The scan report.

        Returns
        -------
        str
            A complete SVG document as a string.
        """
        level = report.overall_level
        pct = round(report.score * 100)
        base_label = _LEVEL_DISPLAY_NAMES.get(level, level.title())
        message = f"{base_label} {pct}%"
        color = self.COLORS.get(level, self.COLORS["none"]).lstrip("#")
        return self._render_svg(
            label=self._label,
            message=message,
            color=color,
        )

    def save(self, report: BadgeScanReport, path: str) -> str:
        """Write an SVG badge to *path* and return the written path string.

        Parameters
        ----------
        report:
            The scan report to generate the badge from.
        path:
            Filesystem path for the output ``.svg`` file.  Parent
            directories are created automatically.

        Returns
        -------
        str
            The resolved path that was written.
        """
        from pathlib import Path

        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.generate(report), encoding="utf-8")
        return str(target)

    # ------------------------------------------------------------------
    # Internal rendering
    # ------------------------------------------------------------------

    def _render_svg(self, label: str, message: str, color: str) -> str:
        """Render the SVG template with the given *label*, *message*, and *color*.

        Parameters
        ----------
        label:
            Left panel text.
        message:
            Right panel text.
        color:
            Six-digit hex colour WITHOUT a leading ``#``.

        Returns
        -------
        str
            Rendered SVG document string.
        """
        label_width = _text_width(label)
        msg_width = _text_width(message)
        total_width = label_width + msg_width

        # SVG text positions are in 10× coordinates (transform="scale(.1)")
        label_mid = (label_width // 2) * 10
        msg_mid = (label_width + msg_width // 2) * 10

        label_text_length = max(10, (label_width - _PANEL_PADDING * 2)) * 10
        msg_text_length = max(10, (msg_width - _PANEL_PADDING * 2)) * 10

        return _SVG_TEMPLATE.format(
            label=_escape_xml(label),
            message=_escape_xml(message),
            color=color,
            label_width=label_width,
            msg_width=msg_width,
            total_width=total_width,
            label_mid=label_mid,
            msg_mid=msg_mid,
            label_text_length=label_text_length,
            msg_text_length=msg_text_length,
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _text_width(text: str) -> int:
    """Estimate the pixel width of *text* in the badge font."""
    return int(len(text) * _CHARS_PER_PX) + _PANEL_PADDING * 2


def _escape_xml(text: str) -> str:
    """Escape XML/SVG special characters in *text*."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def is_valid_svg(svg_text: str) -> bool:
    """Return ``True`` when *svg_text* looks like a valid SVG document.

    Performs a lightweight structural check — not a full XML parse.

    Parameters
    ----------
    svg_text:
        The SVG string to validate.

    Returns
    -------
    bool
    """
    stripped = svg_text.strip()
    return stripped.startswith("<svg") and stripped.endswith("</svg>")
