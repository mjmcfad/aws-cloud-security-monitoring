def correlate_ssh_with_cloudtrail(ssh_events, cloudtrail_events):
    alerts = []

    cloudtrail_ips = set(
        e["sourceIP"] for e in cloudtrail_events if e["sourceIP"]
    )

    for ssh_event in ssh_events:
        ip = ssh_event.get("sourceIP")

        if ip and ip in cloudtrail_ips:
            alerts.append({
                "alert": "IP seen in both SSH and CloudTrail activity",
                "sourceIP": ip,
                "severity": "medium"
            })

    return alerts