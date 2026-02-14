from collections import Counter

def detect_failed_login_bursts(events, threshold=3):
    failures = [e for e in events if e["type"] == "failure"]
    count = len(failures)

    if count >= threshold:
        return {
            "alert": "Brute-force login attempt suspected",
            "count": count,
            "severity": "high"
        }
    return None
