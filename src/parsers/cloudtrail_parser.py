import json
import project_root_finder

project_root = project_root_finder.root
cloudtrail_log_path = project_root / "data" / "raw" / "sample_cloudtrail.json"

def load_cloudtrail_log(filepath):
    with open(filepath, "r") as f:
        data = json.load(f)
    return data["Records"]

def extract_security_events(records):
    events = []
    for r in records:
        events.append({"eventTime": r.get("eventTime"),
            "eventName": r.get("eventName"),
            "eventSource": r.get("eventSource"),
            "sourceIP": r.get("sourceIPAddress"),
            "userType": r.get("userIdentity", {}).get("type"),
            "userName": r.get("userIdentity", {}).get("userName"),
        })
    return events


if __name__ == "__main__":
    records = load_cloudtrail_log(cloudtrail_log_path)
    print(f"Loaded {len(records)} records")

    events = extract_security_events(records)
    for e in events[:5]:
        print(e)
