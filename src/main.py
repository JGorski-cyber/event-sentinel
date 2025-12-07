"""
Main pipeline for the Log Triage & Threat Highlights tool.

Steps:
1. Parse CLI args
2. Load log file(s)
3. Auto-select parser (or use specified type)
4. Convert logs -> Event objects
5. Run detection engine
6. Generate report (console + json/csv)
"""

from pathlib import Path
from .cli import build_cli
from .parsers import PARSERS
from .detector import Detector
from .reporter import Reporter
from .color import color_text, Color


# ------------------------------------------------------------
# Helper: load the right parser
# ------------------------------------------------------------
def choose_parser(log_type, sample_line=None):
    """
    Selects the correct parser based on CLI choice or sample content.
    """

    if log_type != "auto":
        return PARSERS.get(log_type)

    # Auto-detect from content
    if sample_line:
        s = sample_line.lower()

        if "sysmon" in s:
            return PARSERS["sysmon"]

        if "eventlog" in s or "<event" in s:
            return PARSERS["windows"]

        if "http" in s or "GET " in s or "POST " in s:
            return PARSERS["web"]

    return None


# ------------------------------------------------------------
# Helper: read file lines
# ------------------------------------------------------------
def read_file_lines(path: Path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except Exception as e:
        print(color_text(f"[ERROR] Could not read file: {path} ({e})", Color.RED))
        return []


# ------------------------------------------------------------
# Main execution
# ------------------------------------------------------------
def main():
    args = build_cli()

    # Validate input
    if not args.file and not args.directory:
        print(color_text("[ERROR] You must supply --file or --directory", Color.RED))
        return

    # Gather all files into a list
    input_files = []

    if args.file:
        input_files.append(args.file)

    if args.directory:
        for ext in ("*.log", "*.txt", "*.json", "*.csv", "*.xml"):
            input_files.extend(args.directory.glob(ext))

    if not input_files:
        print(color_text("[ERROR] No log files found.", Color.RED))
        return

    reporter = Reporter()
    detector = Detector()

    # ------------------------------------------------------------
    # Process each file
    # ------------------------------------------------------------
    for file_path in input_files:

        print(color_text(f"\n[+] Processing {file_path}", Color.BRIGHT_BLUE))

        lines = read_file_lines(file_path)
        if not lines:
            continue

        # Choose parser (explicit or auto)
        parser_func = choose_parser(args.type, sample_line=lines[0])

        if parser_func is None:
            print(color_text("[!] Unknown log type; skipping file.", Color.YELLOW))
            continue

        # Directly call the parsing function
        events = parser_func(file_path)

        if args.verbose:
            print(color_text(f"  Parsed {len(events)} events", Color.CYAN))

        events = detector.run(events)
        reporter.add_events(events)

    # ------------------------------------------------------------
    # Output summary to console
    # ------------------------------------------------------------
    if not args.no_color:
        reporter.print_summary()
    else:
        # Simple non-colorized output
        for key, data in reporter.summarize_events().items():
            print(f"{key}: {data}")

    # ------------------------------------------------------------
    # Export reports
    # ------------------------------------------------------------
    args.output_path.mkdir(parents=True, exist_ok=True)

    if args.output in ("json", "both"):
        reporter.export_json(args.output_path / "report.json")

    if args.output in ("csv", "both"):
        reporter.export_csv(args.output_path / "report.csv")


# ------------------------------------------------------------

if __name__ == "__main__":
    main()
