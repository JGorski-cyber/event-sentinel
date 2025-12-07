"""
Parses a Sysmon CSV file and returns a list of Event objects.
"""

import csv
from typing import List
from ..event import Event


def parse_sysmon_csv(file_path: str) -> List[Event]:
    
    events = []

    with open(file_path, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            # Extract timestamp and raw fields
            timestamp = row.get("UtcTime") or row.get("EventTime") or "N/A"

            raw = dict(row)

            normalized = {
                "event_id": row.get("EventID"),
                "process_name": row.get("Image") or "",
                "process_path": row.get("Image") or "",
                "command_line": row.get("CommandLine") or "",
                "parent_process": row.get("ParentImage") or "",
                "parent_command_line": row.get("ParentCommandLine") or "",
                "user": row.get("User") or "",
                "src_ip": row.get("SourceIp") or "",
                "dest_ip": row.get("DestinationIp") or "",
            }

            events.append(
                Event(
                    timestamp=timestamp,
                    source="sysmon",
                    raw=raw,
                    normalized=normalized
                )
            )

    return events
