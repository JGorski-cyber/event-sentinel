"""
A normalized representation of a log event.

All parsers produce an Event object so that the rest of the
system (rules engine, reports, output) can work consistently
regardless of log format.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class Event:
    timestamp: str
    source: str                  
    raw: Dict[str, Any]          
    normalized: Dict[str, Any] = field(default_factory=dict)
    detections: List[str] = field(default_factory=list)

    def get(self, key: str, default: Optional[Any] = None) -> Any:
        """Safe dict-like access into normalized fields."""
        return self.normalized.get(key, default)

    def __getitem__(self, key: str) -> Any:
        """event['process_name'] style access."""
        return self.normalized.get(key)
    
    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "raw": self.raw,
            "normalized": self.normalized,
            "detections": self.detections
        }


     # --- Property helpers matching normalized keys ---
    @property
    def message(self):
        return self.normalized.get("message")

    @property
    def description(self):
        return self.normalized.get("description")

    @property
    def process(self):
        return self.normalized.get("process_name")

    @property
    def parent(self):
        return self.normalized.get("parent_process")

    @property
    def command(self):
        return self.normalized.get("command_line")

    @property
    def source_ip(self):
        return self.normalized.get("src_ip")

    @property
    def request(self):
        return self.normalized.get("request")