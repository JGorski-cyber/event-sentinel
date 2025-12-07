import argparse
from pathlib import Path

def build_cli():
    """
    Creates and configures the command-line interface for the tool.
    Returns the parsed arguments for use in main.py.
    """

    parser = argparse.ArgumentParser(
        prog="Log Triage & Threat Highlights",
        description="A beginner-friendly SOC tool for log parsing, detection, and reporting."
    )

    # ---- INPUT OPTIONS ----
    parser.add_argument(
        "-f", "--file",
        type=Path,
        help="Path to a single log file to analyze."
    )

    parser.add_argument(
        "-d", "--directory",
        type=Path,
        help="Path to a directory containing multiple log files."
    )

    parser.add_argument(
        "-t", "--type",
        choices=["sysmon", "windows", "web", "auto"],
        default="auto",
        help="Log type to parse (default: auto-detection)."
    )

    # ---- OUTPUT OPTIONS ----
    parser.add_argument(
        "-o", "--output",
        choices=["json", "csv", "both"],
        default="json",
        help="Output report format (default: JSON)."
    )

    parser.add_argument(
        "--output-path",
        type=Path,
        default=Path("./reports"),
        help='Where to save the generated reports (default path: "./reports").'
    )

    # ---- DISPLAY OPTIONS ----
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colorized console output."
    )

    # ---- DEBUG / VERBOSE ----
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug output for troubleshooting."
    )

    return parser.parse_args()
