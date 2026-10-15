"""
Live-sensor detection report card.

metrics.json is the model's report card on genuine NSL-KDD packet data. THIS is
its report card on the *live capture-proxy sensor* — the distribution the demo
actually runs on. It replays each attack script's real request pattern through
the real capture-proxy FeatureExtractor and runs the result through the backend's
two-tier nids_engine.classify(), then reports the per-class detection rate.

Why this is faithful to the live demo (and diagnose-by-eyeball is not):
  * ONE shared FeatureExtractor, exactly as capture-proxy/proxy.py uses it;
  * normal.py traffic runs UNDERNEATH each attack phase (as `main.py demo` does),
    so the sliding windows carry the same mixed traffic the live sensor sees;
  * a controllable fake clock places requests at each script's real pacing, so
    the per-2s-window `count`/rate features match the live sensor;
  * the attack request pools are IMPORTED from the attack scripts (not copied),
    so this can never silently drift from what the demo sends.

Run:  uv run python eval_sensor.py          (from nids-model/)
      uv run python eval_sensor.py --json    (machine-readable summary)

Exit code is 0 only if every class clears its detection-rate threshold, so this
doubles as a regression gate after a retrain.

This is the OFFLINE replay (simulated clock, synthetic response sizes). The
authoritative live number is the backend's real-time confusion matrix on the
Learning page, which scores every live verdict against the attack scripts'
ground-truth tag.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import types
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "capture-proxy"))
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "nids-model"))

# Import the attack scripts' request pools WITHOUT their network dependency:
# a stub `requests` module lets the modules import so we can read their
# module-level constants (we never call run(), which is the only user of it).
sys.modules.setdefault("requests", types.ModuleType("requests"))
sys.path.insert(0, str(ROOT / "attack-script"))

import config as atk_config            # noqa: E402
import normal as atk_normal            # noqa: E402
import recon as atk_recon              # noqa: E402
import flood as atk_flood              # noqa: E402
import credential as atk_credential    # noqa: E402
import exploit as atk_exploit          # noqa: E402
import novel as atk_novel              # noqa: E402

import feature_extractor as fx_mod     # noqa: E402
from feature_extractor import FeatureExtractor  # noqa: E402
from src.services import nids_engine   # noqa: E402

# ---- controllable fake clock (drives the sensor's sliding windows) ----------
_CLOCK = {"t": 1_000_000.0}
fx_mod.time.time = lambda: _CLOCK["t"]

# ---- request pools, imported straight from the attack scripts ---------------
NORMAL_PATHS = atk_normal.PATHS
RECON_WORDS = atk_recon.WORDLIST
FLOOD_PATH = atk_flood.FLOOD_PATH
AUTH_ENDPOINTS = atk_credential.AUTH_ENDPOINTS
EXPLOIT_PATHS = atk_exploit.EXPLOIT_PATHS
NOVEL_PATHS = atk_novel.NOVEL_PATHS
NOVEL_IPS = atk_novel.NOVEL_IPS
NORMAL_IPS = atk_config.NORMAL_IPS
ATTACKER_IPS = atk_config.ATTACKER_IPS

# Real pages the demo site serves 200; everything else 404 (as the netflix-clone
# does for the attack paths). Under flood some requests time out (no response).
_REAL_PAGES = set(NORMAL_PATHS) | {"/browse"}

# Each generator's realistic request rate (req/s), matching the attack scripts'
# pacing/concurrency, so the 2s-window count/rate features are representative.
RATES = {
    "normal": 0.8, "recon": 40.0, "flood": 120.0,
    "credential": 8.0, "exploit": 5.0, "novel": 2.5,  # novel is deliberately slow
}

# A class passes if at least this fraction of its attack requests are detected as
# the expected class. Novel is special-cased (see run_phase).
PASS_THRESHOLD = 0.75


# Response sizes / durations: drawn from the REAL calibration recording when one
# exists (per NSL-KDD flag, i.e. per HTTP outcome), so the replay sees what the
# live sensor sees for this site; otherwise a generic small-page guess.
def _load_response_pools():
    path = ROOT / "nids-model" / "data" / "live_capture.csv"
    if not path.exists():
        return None
    import csv
    pools: dict = {}
    with path.open(newline="") as fh:
        for r in csv.DictReader(fh):
            pools.setdefault(r["flag"], []).append((int(float(r["dst_bytes"])), float(r["duration"])))
    return pools or None


_POOLS = _load_response_pools()


def _response(status: int | None, rng: random.Random) -> tuple[int, float]:
    flag = fx_mod._flag_from_status(status)
    if _POOLS and _POOLS.get(flag):
        return rng.choice(_POOLS[flag])
    return rng.randint(120, 900), 0.01


def _status(path: str, flood: bool, rng: random.Random) -> int | None:
    p = path.split("?")[0]
    if p in _REAL_PAGES:
        return None if (flood and rng.random() < 0.3) else 200
    return 404


def _make_request(kind: str, rng: random.Random):
    """Return (method, path, ip, is_flood, body_len) for one request of `kind`."""
    if kind == "normal":
        return "GET", rng.choice(NORMAL_PATHS), rng.choice(NORMAL_IPS), False, 0
    if kind == "recon":
        return ("GET", rng.choice(RECON_WORDS) + f"/{rng.randint(1000, 9999)}",
                rng.choice(ATTACKER_IPS), False, 0)
    if kind == "flood":
        return "GET", FLOOD_PATH, rng.choice(ATTACKER_IPS), True, 0
    if kind == "credential":
        return ("POST", rng.choice(AUTH_ENDPOINTS), rng.choice(ATTACKER_IPS),
                False, rng.randint(40, 160))
    if kind == "exploit":
        return (rng.choice(["GET", "GET", "POST"]), rng.choice(EXPLOIT_PATHS),
                rng.choice(ATTACKER_IPS), False, rng.randint(0, 120))
    if kind == "novel":
        return (rng.choice(["POST", "PUT", "PATCH"]), rng.choice(NOVEL_PATHS),
                rng.choice(NOVEL_IPS), False, rng.randint(3000, 9000))
    raise ValueError(kind)


def _phase_events(attack_kind: str, seconds: float, rng: random.Random):
    """Interleave `normal` + `attack_kind` over `seconds`; return time-sorted list."""
    kinds = ("normal",) if attack_kind == "normal" else ("normal", attack_kind)
    events = []
    for kind in kinds:
        rate = RATES[kind]
        t = 0.0
        while t < seconds:
            t += rng.expovariate(rate)
            if t < seconds:
                events.append((t, kind))
    events.sort(key=lambda e: e[0])
    return events


def _novel_learned_as() -> str | None:
    """The class the novel scenario was learned as (data/learned_classes.json),
    if the current model knows it."""
    try:
        learned = json.loads((ROOT / "nids-model" / "data" / "learned_classes.json").read_text())
    except Exception:  # noqa: BLE001
        return None
    known = set(nids_engine.model_classes())
    for name, info in learned.items():
        if info.get("scenario") == "novel" and name in known:
            return name
    return None


def run_phase(attack_kind: str, expected: str, seconds: float, rng: random.Random):
    learned_as = _novel_learned_as() if attack_kind == "novel" else None
    fx = FeatureExtractor()
    base_t = _CLOCK["t"]
    verdicts: Counter = Counter()
    model_only: Counter = Counter()
    novel_flags = 0
    scored = 0
    for (t, kind) in _phase_events(attack_kind, seconds, rng):
        _CLOCK["t"] = base_t + t
        method, path, ip, is_flood, body_len = _make_request(kind, rng)
        st = _status(path, is_flood, rng)
        dst_bytes, duration = _response(st, rng)
        feats = fx.extract(
            path=path, method=method, status=st, duration=duration,
            src_bytes=body_len, dst_bytes=dst_bytes,
            src_ip=ip, user_agent="x",
        )
        if kind != attack_kind:
            continue
        det = nids_engine.classify(feats)
        scored += 1
        verdicts[det["label"]] += 1
        model_only[det.get("model_label")] += 1
        # Novel: flagged by the engine's open-set check (sent to the bucket), or
        # already recognised as the class it was learned as.
        if (det["label"] == learned_as) if learned_as else det.get("novel"):
            novel_flags += 1

    if attack_kind == "novel":
        rate = novel_flags / scored if scored else 0.0
        detected_as = learned_as or "novel/flagged"
    else:
        rate = verdicts.get(expected, 0) / scored if scored else 0.0
        detected_as = expected
    top = verdicts.most_common(1)[0][0] if verdicts else "—"
    return {
        "phase": attack_kind, "expected": detected_as, "scored": scored,
        "rate": round(rate, 3), "top_verdict": top,
        "verdicts": dict(verdicts), "model_only": dict(model_only),
        "flagged_novel": novel_flags,
        "pass": rate >= PASS_THRESHOLD,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Live-sensor detection report card.")
    ap.add_argument("--seconds", type=float, default=6.0, help="sim seconds per phase")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--json", action="store_true", help="emit JSON only")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    if not nids_engine.model_status()["loaded"]:
        print("ERROR: model not loaded — run train.py first.", file=sys.stderr)
        return 2

    phases = [
        ("normal", "Normal"), ("recon", "Probe"), ("flood", "DoS"),
        ("credential", "R2L"), ("exploit", "U2R"), ("novel", "(novel)"),
    ]
    results = [run_phase(k, exp, args.seconds, rng) for k, exp in phases]

    if args.json:
        print(json.dumps({"pass_threshold": PASS_THRESHOLD, "results": results}, indent=2))
        return 0 if all(r["pass"] for r in results) else 1

    print("\n=== LIVE-SENSOR DETECTION REPORT CARD ===")
    print("(response sizes: " + ("drawn from the live recording" if _POOLS else "generic guess - no recording yet") + ")")
    print(f"(replays the real attack scripts through the capture-proxy sensor; "
          f"pass = >={int(PASS_THRESHOLD*100)}% of a class's requests detected)\n")
    for r in results:
        flag = "PASS" if r["pass"] else "FAIL"
        print(f"  [{flag}]  {r['phase']:11s} expected {r['expected']:13s} "
              f"rate {r['rate']*100:5.1f}%   verdicts={r['verdicts']}"
              + (f"   flagged-novel={r['flagged_novel']}" if r["phase"] != "novel" else ""))
    n_pass = sum(r["pass"] for r in results)
    print(f"\n  {n_pass}/{len(results)} phases pass.")
    for r in results:
        if not r["pass"]:
            print(f"    - {r['phase']}: model-only verdicts were {r['model_only']}")
    return 0 if n_pass == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
