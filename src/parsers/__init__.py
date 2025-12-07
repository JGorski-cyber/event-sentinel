from .sysmon_parser import parse_sysmon_csv
from .web_parser import parse_web_logs
from .wevt_parser import parse_wevt_xml

PARSERS = {
    "sysmon": parse_sysmon_csv,
    "web": parse_web_logs,
    "windows": parse_wevt_xml,
}
