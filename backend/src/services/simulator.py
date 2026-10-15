import asyncio
import random
import time
from typing import Optional, Dict, Any, List

from src.models.traffic import TrafficEvent
from src.storage.memory import traffic_events, simulation_state
from src.websocket.manager import manager
from src.services import nids_engine
from src.services.drift_engine import get_cached_drift


NORMAL_IPS = [
    "198.51.100.14", "198.51.100.22", "203.0.113.88", "203.0.113.104",
    "192.168.1.105", "192.168.1.112", "172.16.0.42", "72.14.192.1"
]

BOTNET_IPS = [
    "185.220.101.5", "185.220.101.44", "185.220.102.78", "45.83.223.12",
    "45.83.223.99", "103.21.244.15", "103.21.244.201", "194.26.29.11"
]

NORMAL_PATHS = [
    "/", "/browse", "/watch/101", "/watch/204", "/movies",
    "/latest", "/my-list", "/api/user/profile"
]

ATTACK_PATHS = [
    "/admin/config.json", "/.env", "/api/v1/debug?dump=true",
    "/api/internal/users/all", "/v2/auth/bypass", "/phpmyadmin/index.php",
    "/cgi-bin/test-cmd", "/api/v1/exec?cmd=id"
]

USER_AGENTS_NORMAL = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
]

USER_AGENTS_ATTACK = [
    "sqlmap/1.7.11#stable",
    "Nikto/2.1.6",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
]


async def generate_simulated_event(
    mode: str = "normal",
    custom_ip: Optional[str] = None,
    custom_path: Optional[str] = None
) -> TrafficEvent:
    now_ms = time.time() * 1000.0

    if custom_ip:
        ip = custom_ip
    elif mode == "spike" or mode == "gradual":
        ip = random.choice(BOTNET_IPS if random.random() > 0.3 else NORMAL_IPS)
    else:
        ip = random.choice(NORMAL_IPS)

    if custom_path:
        path = custom_path
    elif mode == "spike" or mode == "gradual":
        path = random.choice(ATTACK_PATHS if random.random() > 0.4 else NORMAL_PATHS)
    else:
        path = random.choice(NORMAL_PATHS)

    method = "GET" if mode == "normal" else random.choice(["GET", "POST", "PUT", "DELETE"])
    ua = random.choice(USER_AGENTS_ATTACK if (mode in ["spike", "gradual"] and random.random() > 0.4) else USER_AGENTS_NORMAL)

    depth = len([p for p in path.split("/") if p])
    content_len = random.randint(0, 150) if mode == "normal" else random.randint(500, 8500)
    query_str = "?debug=true&param=" + str(random.randint(100, 999)) if (mode in ["spike", "gradual"] or "?" in path) else ""
    query_count = 2 if query_str else 0

    event = TrafficEvent(
        timestamp=now_ms,
        path=path,
        full_url=f"http://localhost:3000{path}{query_str}",
        method=method,
        ip=ip,
        user_agent=ua,
        referer="http://localhost:3000/",
        host="localhost:3000",
        origin="http://localhost:3000",
        content_length=content_len,
        content_type="application/json",
        accept="*/*",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate",
        cache_control="no-cache" if mode != "normal" else "max-age=0",
        connection="keep-alive",
        query_string=query_str,
        query_param_count=query_count,
        path_depth=depth,
        protocol="http",
        sec_fetch_site="same-origin",
        sec_fetch_mode="cors",
        sec_fetch_dest="empty",
    )
    return event


async def start_simulation_task(
    mode: str = "normal",
    count: int = 50,
    delay: float = 0.1,
    custom_ip: Optional[str] = None,
    custom_path: Optional[str] = None
):
    """Asynchronous background worker for traffic simulation."""
    simulation_state["active"] = True
    simulation_state["mode"] = mode
    simulation_state["requests_sent"] = 0
    simulation_state["target_ip"] = custom_ip or "Multiple Pool IPs"

    try:
        for i in range(count):
            if not simulation_state["active"]:
                break

            event = await generate_simulated_event(mode=mode, custom_ip=custom_ip, custom_path=custom_path)
            traffic_events.append(event)
            simulation_state["requests_sent"] += 1

            # Run the simulated event through the NIDS model too, so the
            # dashboard buttons demonstrate live classification.
            detection = nids_engine.classify(nids_engine.features_from_event(event))
            nids_engine.record_detection(detection, {"src_ip": event.ip, "path": event.path})

            # Broadcast over WebSocket
            await manager.broadcast({
                "type": "traffic",
                "timestamp": event.timestamp,
                "path": event.path,
                "method": event.method,
                "ip": event.ip,
                "content_length": event.content_length,
                "path_depth": event.path_depth,
                "user_agent": event.user_agent,
                "detection": detection,
                "threat_summary": nids_engine.threat_summary(),
                "drift": get_cached_drift(),
            })

            # Calculate dynamic delay based on mode
            if mode == "spike":
                current_delay = max(0.01, delay / 5.0)
            elif mode == "gradual":
                current_delay = max(0.02, delay * (1.0 - (i / float(count))))
            else:
                current_delay = delay

            await asyncio.sleep(current_delay)

    finally:
        simulation_state["active"] = False
