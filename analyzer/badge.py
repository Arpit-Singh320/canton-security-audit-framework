# analyzer/badge.py

"""
Generates a Shields.io-style SVG badge to display Daml contract audit status.

This script can be used in CI/CD pipelines to automatically generate a badge
reflecting the results of a security scan and commit it to a repository's
README.md file.

Usage:
  python -m analyzer.badge --status passed --output audit-badge.svg
  python -m analyzer.badge --status failed --label "Code Scan" > badge.svg
"""

import argparse
import sys
import math
from typing import Dict

# Standard color palette for status badges, similar to shields.io
COLORS: Dict[str, str] = {
    "passed": "#4c1",
    "failed": "#e05d44",
    "pending": "#dfb317",
    "unknown": "#9f9f9f",
    "label": "#555",
}

# SVG template based on the classic Shields.io design.
# It uses textLength for better text fitting and is accessible via `role` and `aria-label`.
SVG_TEMPLATE: str = """<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{total_width}" height="20" role="img" aria-label="{label}: {status}">
  <title>{label}: {status}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="{label_color}"/>
    <rect x="{label_width}" width="{status_width}" height="20" fill="{status_color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="{label_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{label_text_len}">{label}</text>
    <text x="{label_x}" y="140" transform="scale(.1)" fill="#fff" textLength="{label_text_len}">{label}</text>
    <text aria-hidden="true" x="{status_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{status_text_len}">{status}</text>
    <text x="{status_x}" y="140" transform="scale(.1)" fill="#fff" textLength="{status_text_len}">{status}</text>
  </g>
</svg>
"""

def _get_text_width(text: str) -> int:
    """
    Estimates the pixel width of a string for the SVG badge.

    This is a simple heuristic and does not perform real font rendering. It's
    tuned to look good with the "Verdana,Geneva,DejaVu Sans,sans-serif" font stack
    used in the SVG template.

    Args:
        text: The string to measure.

    Returns:
        An estimated width in pixels.
    """
    # Horizontal padding on each side of the text
    padding = 10
    # Average width per character, empirically determined
    char_width_factor = 7
    return len(text) * char_width_factor + padding

def generate_badge(label: str, status: str) -> str:
    """
    Generates an SVG badge string for the given label and status.

    Args:
        label: The text for the left-hand side of the badge.
        status: The audit status (e.g., "passed", "failed"). This determines
                the color and text of the right-hand side.

    Returns:
        A string containing the complete SVG for the badge.
    """
    status_lower = status.lower()
    status_text = status.capitalize()

    # Default to "unknown" if an unsupported status is provided
    if status_lower not in COLORS:
        status_lower = "unknown"
        status_text = "Unknown"

    label_width = _get_text_width(label)
    status_width = _get_text_width(status_text)
    total_width = label_width + status_width

    # The SVG template uses a coordinate system scaled by 10 for fonts
    # to allow for sub-pixel precision. We must adjust our calculations accordingly.
    params = {
        "total_width": total_width,
        "label": label,
        "status": status_text,
        "label_width": label_width,
        "status_width": status_width,
        "label_color": COLORS["label"],
        "status_color": COLORS[status_lower],
        "label_x": math.floor(label_width / 2 * 10),
        "status_x": math.floor((label_width + status_width / 2) * 10),
        # textLength is also scaled by 10 to match the transform
        "label_text_len": (label_width - 10) * 10,
        "status_text_len": (status_width - 10) * 10,
    }

    return SVG_TEMPLATE.format(**params).strip()

def main() -> None:
    """
    Parses command-line arguments and generates the audit status badge.
    """
    parser = argparse.ArgumentParser(
        description="Generate an SVG badge for Canton Daml security audit status.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--status",
        required=True,
        choices=["passed", "failed", "pending", "unknown"],
        type=str.lower,
        help="The audit status to display on the badge."
    )
    parser.add_argument(
        "--label",
        default="Security Audit",
        help="The text for the left side of the badge (default: 'Security Audit')."
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path for the SVG. Prints to stdout if not specified."
    )

    args = parser.parse_args()

    svg_content = generate_badge(args.label, args.status)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(svg_content + "\n")
            print(f"Badge successfully written to {args.output}", file=sys.stderr)
        except IOError as e:
            print(f"Error writing to file {args.output}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Print directly to stdout for piping
        print(svg_content)


if __name__ == "__main__":
    main()