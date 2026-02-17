def correlate_ssh_with_cloudtrail(ssh_events, cloudtrail_events):
    alerts = []

    cloudtrail_ips = set(
        e["sourceIP"] for e in cloudtrail_events if e["sourceIP"]
    )

    ssh_ips = set(
        e["sourceIP"] for e in ssh_events if e["sourceIP"]
    )

    overlapping_ips = ssh_ips.intersection(cloudtrail_ips)

    for ip in overlapping_ips:
        alerts.append({
            "alert": "IP seen in both SSH and CloudTrail activity",
            "sourceIP": ip,
            "severity": "medium"
        })

    return alerts