"""
This module runs detection logic against Event objects using
regex-based rules defined in rules.py.

It enriches events with detection tags such as:
- failed_login
- suspicious_process
- base64_command
- rare_external_ip
- web_attack
"""

from . import rules


class Detector:
    def __init__(self):
        pass

    def run(self, events):
        
        for event in events:
            tags = []

            # 1. Failed logins
            if rules.failed_login(event):
                tags.append("failed_login")

            # 2. Suspicious parent-child processes
            if rules.suspicious_process(event):
                tags.append("suspicious_process")

            # 3. Base64 encoded commands
            if rules.base64_command(event):
                tags.append("base64_command")

            # 4. Rare external IPs (web logs only)
            if rules.rare_external_ip(event):
                tags.append("rare_external_ip")

            # 5. Web attack patterns (SQLi, traversal, RCE)
            if rules.web_attack(event):
                tags.append("web_attack")
            
            # 6. Suspicious binary
            if rules.suspicious_binary(event):
                tags.append("suspicious_binary")

            # Attach tags to event object
            event.detections = tags

        return events
