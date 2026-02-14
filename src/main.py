from parsers.auth_log_parser import load_auth_log, parse_auth_events
from parsers.cloudtrail_parser import load_cloudtrail_log, extract_security_events
from detection.ssh_rules import detect_failed_login_bursts
from detection.correlation_rules import correlate_ssh_with_cloudtrail

# Load logs
auth_lines = load_auth_log("data/raw/sample_auth.log")
ssh_events = parse_auth_events(auth_lines)

cloud_records = load_cloudtrail_log("data/raw/sample_cloudtrail.json")
cloud_events = extract_security_events(cloud_records)

# SSH detection
ssh_alert = detect_failed_login_bursts(ssh_events)
if ssh_alert:
    print("SSH ALERT:", ssh_alert)

# Correlation detection
correlation_alerts = correlate_ssh_with_cloudtrail(ssh_events, cloud_events)

for alert in correlation_alerts:
    print("CORRELATION ALERT:", alert)
