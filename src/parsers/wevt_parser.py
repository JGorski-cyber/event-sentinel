"""
Parses a Windows Event Log XML exported from Event Viewer.
Returns a list of Event objects.
"""

import xml.etree.ElementTree as ET
from typing import List
from ..event import Event


def parse_wevt_xml(file_path: str) -> List[Event]:
    tree = ET.parse(file_path)
    root = tree.getroot()
    events = []

    for xml_event in root.findall(".//Event"):
        # --- System section ---
        system = xml_event.find("System")
        timestamp = "N/A"
        event_id = None

        if system is not None:
            time_el = system.find("TimeCreated")
            timestamp = time_el.get("SystemTime") if time_el is not None else "N/A"

            event_id_el = system.find("EventID")
            event_id = event_id_el.text if event_id_el is not None else None

        # --- EventData section ---
        event_data = xml_event.find("EventData")
        raw = {}
        normalized = {
            "event_id": event_id,
            "timestamp": timestamp,
            "user": "",
            "logon_type": "",
            "src_ip": "",
            "process_name": "",
            "process_id": "",
            "command_line": "",
        }

        if event_data is not None:
            for data in event_data.findall("Data"):
                name = data.get("Name", "")
                value = data.text or ""
                raw[name] = value

                # Map to normalized fields
                if name == "TargetUserName":
                    normalized["user"] = value
                elif name == "LogonType":
                    normalized["logon_type"] = value
                elif name in ("IpAddress", "Ip"):
                    normalized["src_ip"] = value
                elif name in ("NewProcessName", "ProcessName"):
                    normalized["process_name"] = value
                elif name == "ProcessId":
                    normalized["process_id"] = value
                elif name == "CommandLine":
                    normalized["command_line"] = value

        events.append(
            Event(
                timestamp=timestamp,
                source="windows_event",
                raw=raw,
                normalized=normalized
            )
        )

    return events
