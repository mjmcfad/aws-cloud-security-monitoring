import project_root_finder
import re

project_root = project_root_finder.root
auth_log_path = project_root / "data" / "raw" / "sample_auth.log"

def load_auth_log(filepath):
    with open(filepath, "r") as f:
        return f.readlines()

def parse_auth_events(lines):
    events = []
    for line in lines:
        if "Accepted" in line or "Invalid" in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            ip = ip_match.group(1) if ip_match else None

            events.append({
                "raw": line.strip(),
                "type": "success" if "Accepted" in line else "failure",
                "sourceIP": ip
            })
    return events

if __name__ == "__main__":
    lines = load_auth_log(auth_log_path)
    events = parse_auth_events(lines)

    print(f"Parsed {len(events)} auth events")
    for e in events[:5]:
        print(e)
