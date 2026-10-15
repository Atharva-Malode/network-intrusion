from collections import deque
from typing import List, Dict, Any, Optional
import time
import random

# In-memory storage for real-time telemetry events
traffic_events: deque = deque(maxlen=10000)

# Baseline window (clean reference benchmark window)
baseline_events: deque = deque(maxlen=1000)

# System status & active simulation state
simulation_state: Dict[str, Any] = {
    "active": False,
    "mode": "idle",
    "requests_sent": 0,
    "target_ip": None,
}

# Pre-seed baseline with clean benchmark traffic events
def seed_initial_baseline():
    if len(baseline_events) > 0:
        return

    from src.models.traffic import TrafficEvent

    normal_ips = [
        "198.51.100.14", "198.51.100.22", "203.0.113.88", "203.0.113.104",
        "192.168.1.105", "192.168.1.112", "172.16.0.42", "72.14.192.1"
    ]
    normal_paths = ["/", "/browse", "/movies", "/latest", "/my-list"]
    user_agents = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Firefox/121.0"
    ]

    base_time = (time.time() - 3600) * 1000.0  # 1 hour ago

    for i in range(250):
        t = base_time + (i * 1200) + random.randint(0, 300)  # ~0.8 req/sec delay
        path = random.choice(normal_paths)
        ip = random.choice(normal_ips)
        ua = random.choice(user_agents)
        depth = len([p for p in path.split("/") if p])

        event = TrafficEvent(
            timestamp=t,
            path=path,
            full_url=f"http://localhost:3000{path}",
            method="GET",
            ip=ip,
            user_agent=ua,
            referer="http://localhost:3000/",
            host="localhost:3000",
            origin="http://localhost:3000",
            content_length=random.randint(0, 50),
            content_type="text/html",
            accept="text/html,application/xhtml+xml",
            accept_language="en-US,en;q=0.9",
            accept_encoding="gzip, deflate",
            cache_control="max-age=0",
            connection="keep-alive",
            query_string="",
            query_param_count=0,
            path_depth=depth,
            protocol="http",
            sec_fetch_site="same-origin",
            sec_fetch_mode="navigate",
            sec_fetch_dest="document",
        )
        baseline_events.append(event)

# Call seed function on module load
seed_initial_baseline()