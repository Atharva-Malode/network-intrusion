"""
NSL-KDD feature sensor.

Turns each observed HTTP request/response into an NSL-KDD-style 41-feature
connection record so the pretrained model can classify it live.

FEATURE-MAPPING HONESTY NOTE
----------------------------
NSL-KDD was built from packet/flow captures, so some of its 41 features are not
directly observable from an application-layer HTTP proxy (e.g. root_shell,
num_root). This sensor computes the *observable* ones exactly (byte counts,
duration, and the time/host window statistics that encode DoS and Probe) and
derives the content-based ones from HTTP attack indicators (sensitive-path
access, failed auth, RCE tokens in the URL). The rate/window features -- which
are what NSL-KDD actually uses to encode flooding and scanning -- carry the bulk
of the live signal. This is a best-effort sensor, documented as such; the model
itself is trained and evaluated on genuine NSL-KDD data.

WINDOW SCOPE
------------
NSL-KDD's 2-second "time-based" features are keyed on the destination host. This
sensor protects exactly ONE host, so a purely destination-keyed window would make
every client share the attacker's statistics: an innocent browser request that
lands inside a 404 storm would inherit rerror_rate ~1.0 and read as a Probe. The
2-second window is therefore scoped to the (source -> this host) pair: count,
srv_count and the error / same-srv / diff-srv rates describe what THIS client did
in the last 2 seconds. The 100-connection dst_host_* window stays destination-
wide, as in NSL-KDD, so a botnet that rotates source IPs is still visible there.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, Optional
from urllib.parse import unquote

# NSL-KDD windows: time-based features look back 2 seconds; host-based
# features look back over the last 100 connections to the destination host.
TIME_WINDOW_SEC = 2.0
HOST_WINDOW_CONNS = 100
# Cap the 2s window so per-request rate stats stay O(1)-ish under heavy floods
# (a flood still pins `count` at this cap, which is well above the DoS threshold).
TIME_WINDOW_MAX = 800

# Flags that NSL-KDD counts as "SYN errors" (server never completed the conn).
SERROR_FLAGS = {"S0", "S1", "S2", "S3"}

# HTTP attack-indicator vocabularies used to derive content-based features.
SENSITIVE_PATHS = (
    "/.env", "/admin", "/config", "/phpmyadmin", "/.git", "/wp-admin",
    "/.aws", "/actuator", "/server-status", "/.ssh", "/backup",
)
RCE_TOKENS = (
    "exec", "cmd=", "/cgi-bin", "shell", "/bin/", "passwd", "system(",
    ";id", "|id", "/etc/", "eval(", "wget ", "curl ", "..%2f", "../",
)
AUTH_PATHS = ("login", "auth", "signin", "session", "token", "oauth", "bypass")


@dataclass
class ConnRecord:
    ts: float
    src_ip: str
    service_key: str
    flag: str


def _flag_from_status(status: Optional[int]) -> str:
    """Map an HTTP outcome to an NSL-KDD TCP flag."""
    if status is None:
        return "S0"            # no response / timeout -> looks like a SYN error
    if status >= 500:
        return "S0"            # server failure
    if status >= 400:
        return "REJ"           # rejected (404/403/401 dominate scans)
    return "SF"                # normally established & terminated


def _service_key(path: str) -> str:
    """Coarse per-endpoint service identity, used for srv/diff-srv windowing."""
    segs = [p for p in path.split("?")[0].split("/") if p]
    return segs[0].lower() if segs else "root"


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


class FeatureExtractor:
    """Sliding-window sensor shared across all proxied requests."""

    def __init__(self) -> None:
        # Destination-wide 2s window (only used for srv_diff_host_rate, which by
        # definition looks across sources) + one 2s window per source IP.
        self.time_window: Deque[ConnRecord] = deque(maxlen=TIME_WINDOW_MAX)
        self.src_windows: Dict[str, Deque[ConnRecord]] = {}
        self.host_window: Deque[ConnRecord] = deque(maxlen=HOST_WINDOW_CONNS)

    def _src_window(self, src_ip: str, cutoff: float) -> Deque[ConnRecord]:
        win = self.src_windows.get(src_ip)
        if win is None:
            win = self.src_windows[src_ip] = deque(maxlen=TIME_WINDOW_MAX)
        # Drop idle sources so the dict cannot grow without bound.
        if len(self.src_windows) > 5000:
            for ip in [ip for ip, w in self.src_windows.items() if not w or w[-1].ts < cutoff]:
                if ip != src_ip:
                    del self.src_windows[ip]
        return win

    def extract(
        self,
        *,
        path: str,
        method: str,
        status: Optional[int],
        duration: float,
        src_bytes: int,
        dst_bytes: int,
        src_ip: str,
        user_agent: str,
    ) -> Dict[str, Any]:
        now = time.time()
        flag = _flag_from_status(status)
        service_key = _service_key(path)
        cur = ConnRecord(ts=now, src_ip=src_ip, service_key=service_key, flag=flag)

        # Advance all windows with the current connection.
        cutoff = now - TIME_WINDOW_SEC
        self.time_window.append(cur)
        while self.time_window and self.time_window[0].ts < cutoff:
            self.time_window.popleft()
        src_win = self._src_window(src_ip, cutoff)
        src_win.append(cur)
        while src_win and src_win[0].ts < cutoff:
            src_win.popleft()
        self.host_window.append(cur)

        # --- time-based traffic features (this source, past 2s) ---
        recent = list(src_win)
        count = len(recent)
        srv = [r for r in recent if r.service_key == service_key]
        srv_count = len(srv)
        serror_rate = _rate(sum(r.flag in SERROR_FLAGS for r in recent), count)
        rerror_rate = _rate(sum(r.flag == "REJ" for r in recent), count)
        srv_serror_rate = _rate(sum(r.flag in SERROR_FLAGS for r in srv), srv_count)
        srv_rerror_rate = _rate(sum(r.flag == "REJ" for r in srv), srv_count)
        same_srv_rate = _rate(srv_count, count)
        diff_srv_rate = _rate(count - srv_count, count)
        # Same service, any source, past 2s: share coming from OTHER sources.
        all_srv = [r for r in self.time_window if r.service_key == service_key]
        srv_diff_host_rate = _rate(
            sum(1 for r in all_srv if r.src_ip != src_ip), len(all_srv)
        )

        # --- host-based traffic features (past 100 conns) ---
        host = list(self.host_window)
        dst_host_count = len(host)
        dst_srv = [r for r in host if r.service_key == service_key]
        dst_host_srv_count = len(dst_srv)
        dst_host_same_srv_rate = _rate(dst_host_srv_count, dst_host_count)
        dst_host_diff_srv_rate = _rate(dst_host_count - dst_host_srv_count, dst_host_count)
        dst_host_same_src_port_rate = _rate(
            sum(1 for r in host if r.src_ip == src_ip), dst_host_count
        )
        dst_host_srv_diff_host_rate = _rate(
            sum(1 for r in dst_srv if r.src_ip != src_ip), dst_host_srv_count
        )
        dst_host_serror_rate = _rate(sum(r.flag in SERROR_FLAGS for r in host), dst_host_count)
        dst_host_srv_serror_rate = _rate(sum(r.flag in SERROR_FLAGS for r in dst_srv), dst_host_srv_count)
        dst_host_rerror_rate = _rate(sum(r.flag == "REJ" for r in host), dst_host_count)
        dst_host_srv_rerror_rate = _rate(sum(r.flag == "REJ" for r in dst_srv), dst_host_srv_count)

        # --- content-based features derived from HTTP attack indicators ---
        # NOTE: the demo site has no real auth/admin routes, so these key off the
        # request PATH rather than the (usually 404) status, which is how an HTTP
        # WAF-style sensor flags intent regardless of whether the route exists.
        # `path` includes the query string and is percent-decoded, because that
        # is where traversal / command payloads live (?page=../../etc/passwd).
        p_low = unquote(path).lower()
        is_auth = any(a in p_low for a in AUTH_PATHS)
        rce_hits = sum(1 for t in RCE_TOKENS if t in p_low)
        hot = sum(1 for s in SENSITIVE_PATHS if s in p_low)

        # An auth-path request that does not succeed (2xx) counts as a failed
        # login attempt -> the dominant R2L signal (guess_passwd family).
        failed_login = 1 if (is_auth and (status is None or status >= 400)) else 0
        # RCE indicates the attacker is executing code (U2R presumes a session).
        logged_in = 1 if (rce_hits > 0 or (is_auth and status is not None and status < 400)) else 0
        root_shell = 1 if rce_hits > 0 else 0
        num_shells = 1 if rce_hits > 0 else 0
        num_access_files = hot
        num_file_creations = 1 if rce_hits > 0 and method in ("POST", "PUT") else 0

        return {
            # basic connection features
            "duration": round(duration, 4),
            "protocol_type": "tcp",
            "service": "http",
            "flag": flag,
            "src_bytes": int(src_bytes),
            "dst_bytes": int(dst_bytes),
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            # content features (HTTP-derived)
            "hot": hot + rce_hits,
            "num_failed_logins": failed_login,
            "logged_in": logged_in,
            "num_compromised": rce_hits,
            "root_shell": root_shell,
            "su_attempted": 0,
            "num_root": rce_hits,
            "num_file_creations": num_file_creations,
            "num_shells": num_shells,
            "num_access_files": num_access_files,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            # time-based traffic features
            "count": count,
            "srv_count": srv_count,
            "serror_rate": serror_rate,
            "srv_serror_rate": srv_serror_rate,
            "rerror_rate": rerror_rate,
            "srv_rerror_rate": srv_rerror_rate,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "srv_diff_host_rate": srv_diff_host_rate,
            # host-based traffic features
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": dst_host_same_srv_rate,
            "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
            "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
            "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,
            "dst_host_serror_rate": dst_host_serror_rate,
            "dst_host_srv_serror_rate": dst_host_srv_serror_rate,
            "dst_host_rerror_rate": dst_host_rerror_rate,
            "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate,
        }
