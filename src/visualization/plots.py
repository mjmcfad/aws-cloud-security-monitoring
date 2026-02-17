import matplotlib.pyplot as plt
from collections import Counter

def plot_ssh_activity(ssh_events):
    types = [e["type"] for e in ssh_events]
    counts = Counter(types)

    labels = counts.keys()
    values = counts.values()

    plt.figure()
    plt.bar(labels, values)
    plt.title("SSH Authentication Activity")
    plt.xlabel("Event Type")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig("ssh_activity.png")
    plt.close()

def plot_cloudtrail_activity(cloud_events, top_n=10):
    event_names = [e["eventName"] for e in cloud_events if e["eventName"]]
    counts = Counter(event_names)

    top_events = sorted(counts.most_common(top_n), key=lambda x: x[1])

    labels = [e[0] for e in top_events]
    values = [e[1] for e in top_events]

    plt.figure(figsize=(10, 6))
    plt.barh(labels, values)
    plt.title(f"Top {top_n} CloudTrail API Events")
    plt.xlabel("Count")
    plt.ylabel("Event Name")
    plt.tight_layout()
    plt.savefig("cloudtrail_activity.png")
    plt.close()
    