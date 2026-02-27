"""SVG badge generator for OWASP ASI compliance certification levels.

Generates shields.io-style flat badges as SVG strings.  Each badge has a
left panel labelled ``"OWASP ASI"`` and a right panel showing the
certification level label.  Colours follow the same semantic conventions
used by shields.io:

- Advanced → green  (#44cc11)
- Standard → blue   (#007ec6)
- Basic    → yellow (#dfb317)
- None     → red    (#e05d44)

The SVG uses standard SVG 1.1 elements so it renders correctly in all
modern browsers and in GitHub README files.

Usage
-----
>>> from aumos_owasp_defenses.certification.badge import BadgeGenerator
>>> from aumos_owasp_defenses.certification.levels import CertificationLevel
>>> gen = BadgeGenerator()
>>> svg = gen.generate(CertificationLevel.ADVANCED)
>>> svg.startswith("<svg")
True
>>> "ASI Advanced" in svg
True
"""
from __future__ import annotations

import re

from aumos_owasp_defenses.certification.levels import CertificationLevel


# ---------------------------------------------------------------------------
# SVG template
# ---------------------------------------------------------------------------

# A flat shields.io-style badge.
# Template variables:
#   {label}       — left panel text  ("OWASP ASI")
#   {message}     — right panel text ("ASI Advanced", etc.)
#   {color}       — right panel fill hex colour (without #)
#   {label_width} — pixel width of the left panel
#   {msg_width}   — pixel width of the right panel
#   {total_width} — label_width + msg_width
#   {label_mid}   — midpoint x of label panel (for text anchor)
#   {msg_mid}     — midpoint x of message panel (for text anchor)
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

#: Left panel label text.
_BADGE_LABEL: str = "OWASP ASI"

#: Approximate pixel width per character for the badge font at font-size 11.
_CHARS_PER_PX: float = 6.5

#: Fixed horizontal padding (px) added on each side of each panel's text.
_PANEL_PADDING: int = 10


# ---------------------------------------------------------------------------
# BadgeGenerator
# ---------------------------------------------------------------------------


class BadgeGenerator:
    """Generate SVG compliance badges for OWASP ASI certification levels.

    The generator is stateless and safe for concurrent use.

    Parameters
    ----------
    label:
        The left-panel text.  Defaults to ``"OWASP ASI"``.

    Example
    -------
    >>> gen = BadgeGenerator()
    >>> svg = gen.generate(CertificationLevel.BASIC)
    >>> "<svg" in svg
    True
    >>> "ASI Basic" in svg
    True
    """

    def __init__(self, label: str = _BADGE_LABEL) -> None:
        self._label = label

    def generate(self, level: CertificationLevel) -> str:
        """Generate an SVG badge string for *level*.

        Parameters
        ----------
        level:
            The certification level to represent in the badge.

        Returns
        -------
        str
            A complete SVG document as a string.
        """
        message = level.display_name()
        color = level.badge_color().lstrip("#")
        return _render_badge(
            label=self._label,
            message=message,
            color=color,
        )

    def generate_for_result(
        self,
        level: CertificationLevel,
        score: float,
    ) -> str:
        """Generate a badge embedding the numeric overall score.

        The right panel shows the level name followed by the score as a
        percentage, e.g. ``"ASI Advanced 100%"``.

        Parameters
        ----------
        level:
            Certification level to display.
        score:
            Overall score in ``[0.0, 1.0]``.

        Returns
        -------
        str
            A complete SVG document as a string.
        """
        pct = round(score * 100)
        message = f"{level.display_name()} {pct}%"
        color = level.badge_color().lstrip("#")
        return _render_badge(
            label=self._label,
            message=message,
            color=color,
        )

    def save(self, level: CertificationLevel, path: str) -> str:
        """Write an SVG badge to *path* and return the resolved path string.

        Parameters
        ----------
        level:
            The certification level to represent.
        path:
            Filesystem path for the output ``.svg`` file.

        Returns
        -------
        str
            The path that was written.
        """
        from pathlib import Path

        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.generate(level), encoding="utf-8")
        return str(target)


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------


def _text_width(text: str) -> int:
    """Estimate the pixel width of *text* in the badge font.

    Returns an integer number of pixels suitable for panel sizing.
    """
    return int(len(text) * _CHARS_PER_PX) + _PANEL_PADDING * 2


def _render_badge(label: str, message: str, color: str) -> str:
    """Render the SVG template with the given label, message, and colour.

    Parameters
    ----------
    label:
        Left panel text.
    message:
        Right panel text.
    color:
        Six-digit hex colour string without leading ``#``.

    Returns
    -------
    str
        Rendered SVG document.
    """
    label_width = _text_width(label)
    msg_width = _text_width(message)
    total_width = label_width + msg_width

    # SVG text positions are in 10× coordinates (transform="scale(.1)"), so
    # multiply logical pixel midpoints by 10.
    label_mid = (label_width // 2) * 10
    msg_mid = (label_width + msg_width // 2) * 10

    # textLength attributes guide letter-spacing; keep proportional to width.
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


def _escape_xml(text: str) -> str:
    """Escape characters that have special meaning in XML/SVG attributes."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def is_valid_svg(svg_text: str) -> bool:
    """Return ``True`` when *svg_text* appears to be a valid SVG document.

    Checks for the opening ``<svg`` tag and a closing ``</svg>`` tag.
    This is a lightweight structural check, not a full XML parse.

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
