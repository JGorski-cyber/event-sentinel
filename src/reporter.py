"""
Collects Event objects, summarizes them, prints colorized output,
and exports results to JSON or CSV.
"""

import csv
import json
from collections import defaultdict
from .color import color_text, Color


class Reporter:
    
    def __init__(self):
        self.events = []

    def add_events(self, events):
        self.events.extend(events)


    def summarize_events(self):
        """
        Returns a dictionary keyed by (source, event_id) with:
        - count
        - first_seen
        - last_seen
        - sample_events (list of dicts)
        """
        summary = defaultdict(lambda: {
            "count": 0,
            "first_seen": None,
            "last_seen": None,
            "sample_events": []
        })

        for event in self.events:
            key = (event.source, event.normalized.get("event_id", "unknown"))
            entry = summary[key]

            # Increment count
            entry["count"] += 1

            # First/last seen timestamps
            if entry["first_seen"] is None or event.timestamp < entry["first_seen"]:
                entry["first_seen"] = event.timestamp

            if entry["last_seen"] is None or event.timestamp > entry["last_seen"]:
                entry["last_seen"] = event.timestamp

            # Store sample events (max 3)
            if len(entry["sample_events"]) < 3:
                entry["sample_events"].append(event.to_dict())

        return summary


    # ------------------------------------------------------------
    # Console Output
    # ------------------------------------------------------------
    def print_summary(self):
        summary = self.summarize_events()

        print(color_text("\n=== Log Triage Summary ===\n", Color.BRIGHT_YELLOW))

        for (source, event_id), data in summary.items():
            print(color_text(f"[{source}] Event ID {event_id}", Color.BRIGHT_BLUE))
            print(color_text(f"  Count: {data['count']}", Color.GREEN))
            print(color_text(f"  First Seen: {data['first_seen']}", Color.CYAN))
            print(color_text(f"  Last Seen:  {data['last_seen']}", Color.CYAN))

            print(color_text("  Sample Events:", Color.BRIGHT_MAGENTA))
            for sample in data["sample_events"]:
                print("   •", sample)

                # Add colorized detections line
                detections = sample.get("detections", [])
                if detections:
                    colored_tags = ", ".join([color_text(tag, Color.RED) for tag in detections])
                    print(f"     Detections: {colored_tags}")
                else:
                    print(f"     Detections: {color_text('None', Color.BRIGHT_GREEN)}")

            print()

    # ------------------------------------------------------------
    # Export JSON
    # ------------------------------------------------------------
    def export_json(self, filepath):
        summary = self.summarize_events()
        json_ready = {}

        for (source, event_id), data in summary.items():
            key = f"{source}:{event_id}"
            json_ready[key] = data

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(json_ready, f, indent=4, default=str)

        print(color_text(f"[+] JSON report saved to {filepath}", Color.GREEN))

    # ------------------------------------------------------------
    # Export CSV
    # ------------------------------------------------------------
   
    import csv

    def export_csv(self, filepath):
        
        all_events = self.events  

        if not all_events:
            print("[!] No events to export.")
            return

        # Dynamically collect all normalized keys across events
        normalized_keys = set()
        for e in all_events:
            normalized_keys.update(e.normalized.keys())

        # Build headers
        headers = ["timestamp", "source"] + sorted(normalized_keys) + ["detections"]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for e in all_events:
                row = [
                    e.timestamp,
                    e.source
                ]
                for key in sorted(normalized_keys):
                    row.append(e.normalized.get(key, ""))
                row.append(";".join(e.detections))
                writer.writerow(row)

        print(color_text(f"[+] CSV report saved to {filepath}", Color.GREEN))


