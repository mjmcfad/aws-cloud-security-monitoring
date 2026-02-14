from parsers.auth_log_parser import load_auth_log, parse_auth_events
from detection.ssh_rules import detect_failed_login_bursts

lines = load_auth_log("data/raw/sample_auth.log")
events = parse_auth_events(lines)

alert = detect_failed_login_bursts(events)
if alert:
    print(alert)
else:
    print("No suspicious activity detected")
