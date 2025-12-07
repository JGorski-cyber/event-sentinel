"""
Parses generic web server logs (Common Log Format / Combined Log Format).
Returns a list of Event objects.

This parser focuses on Apache/Nginx style access logs.
"""

import re
from typing import List
from ..event import Event


# Common Log Format + optional fields (combined logs)
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) '
    r'(?P<ident>\S*) '
    r'(?P<authuser>\S*) '
    r'\[(?P<timestamp>.+?)\] '
    r'"(?P<request>.*?)" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'
)


def split_request(req: str):
    
    if not req:
        return "", "", ""

    parts = req.split()

    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    elif len(parts) == 2:
        return parts[0], parts[1], ""
    elif len(parts) == 1:
        return parts[0], "", ""
    else:
        return "", "", ""


def parse_web_logs(file_path: str) -> List[Event]:
    
    events = []

    with open(file_path, encoding="utf-8") as f:
        for line in f:
            match = LOG_PATTERN.search(line)
            if not match:
                continue

            raw = match.groupdict()

            method, path, protocol = split_request(raw.get("request", ""))

            normalized = {
                "src_ip": raw.get("ip", ""),
                "method": method,
                "url": path,
                "protocol": protocol,
                "status": int(raw.get("status", 0)),
                "user_agent": raw.get("agent", ""),
                "referrer": raw.get("referrer", ""),
            }

            events.append(
                Event(
                    timestamp=raw.get("timestamp", ""),
                    source="web",
                    raw=raw,
                    normalized=normalized
                )
            )

    return events
