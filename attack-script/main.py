"""
Attack orchestrator.

Usage:
    python main.py <mode>

Modes:
    normal      Legitimate browsing            -> Normal
    recon       Endpoint scanning / probing    -> Probe
    flood       DoS/DDoS flood                 -> DoS
    credential  Auth brute force / stuffing    -> R2L
    exploit     RCE / traversal / LFI          -> U2R
    novel       Unknown pattern                -> collected as NOVEL (label it!)
    demo        Scripted sequence cycling through all phases (great for a live
                walkthrough - watch the dashboard's Threat Classification change)
    calibrate   Record ~40s of every KNOWN class through the real sensor, then
                retrain the model on those recordings (run once per machine,
                before presenting). Novel traffic is never recorded.

All traffic is sent through the capture proxy (see config.TARGET_URL).
Everything runs locally against your own demo site.
"""

import sys
import threading
import time

import requests

import normal
import recon
import flood
import credential
import exploit
import novel
from config import BACKEND_URL

MODES = {
    "normal": normal.run,
    "recon": recon.run,
    "flood": flood.run,
    "credential": credential.run,
    "exploit": exploit.run,
    "novel": novel.run,
}

# Scripted demo: (label, module.run, seconds). Normal traffic runs underneath
# the whole time in a background thread for realistic mixed traffic.
DEMO_SEQUENCE = [
    ("Baseline normal traffic", normal.run, 15),
    ("PROBE  - reconnaissance scan", recon.run, 20),
    ("DoS    - flood attack", flood.run, 20),
    ("R2L    - credential brute force", credential.run, 20),
    ("U2R    - exploitation / RCE", exploit.run, 20),
]


def _run_for(label: str, fn, seconds: int):
    """Run one attack phase for `seconds`, then stop it, so phases never overlap
    (overlapping attacks share source IPs and would blur each other's windows)."""
    print("\n" + "=" * 60)
    print(f"  PHASE: {label}  ({seconds}s)")
    print("=" * 60)
    stop = threading.Event()
    t = threading.Thread(target=fn, kwargs={"stop": stop}, daemon=True)
    t.start()
    time.sleep(seconds)
    stop.set()
    t.join(timeout=10)
    time.sleep(2.5)  # let the sensor's 2s windows drain between phases


def run_demo():
    print("Starting scripted attack demo. Watch the dashboard.")
    # Continuous normal traffic underneath the attack phases.
    threading.Thread(target=normal.run, daemon=True).start()
    for label, fn, secs in DEMO_SEQUENCE:
        _run_for(label, fn, secs)
    print("\nDemo sequence complete. Normal traffic continues until you Ctrl+C.")
    while True:
        time.sleep(1)


# Calibration: each KNOWN class in turn, with normal browsing underneath. The
# backend records every tagged sensor record it classifies (X-Sim-Scenario), so
# the model is then trained on what THIS sensor actually emits for THIS site,
# instead of on hand-written guesses of it.
CALIBRATE_SEQUENCE = [
    ("Normal browsing", None, 40),
    ("Probe  - reconnaissance scan", recon.run, 40),
    ("DoS    - flood attack", flood.run, 40),
    ("R2L    - credential brute force", credential.run, 40),
    ("U2R    - exploitation / RCE", exploit.run, 40),
]


def _capture_counts():
    try:
        r = requests.get(f"{BACKEND_URL}/learning/status", timeout=5)
        return r.json().get("capture", {}).get("counts", {})
    except Exception:
        return {}


def run_calibrate():
    print("Calibrating: recording every known class through the live sensor.")
    print("Keep the backend, demo site and capture proxy running.\n")
    # Several browsers' worth of normal traffic so Normal is well represented.
    for _ in range(3):
        threading.Thread(target=normal.run, daemon=True).start()
    for label, fn, secs in CALIBRATE_SEQUENCE:
        if fn is None:
            print("\n" + "=" * 60 + f"\n  RECORDING: {label}  ({secs}s)\n" + "=" * 60)
            time.sleep(secs)
            continue
        _run_for(f"RECORDING: {label}", fn, secs)
    print(f"\nRecorded rows per class: {_capture_counts()}")
    print("Retraining on NSL-KDD + the recorded live traffic ...")
    try:
        r = requests.post(f"{BACKEND_URL}/learning/retrain", timeout=10)
        print(f"  {r.json().get('status')} - watch progress on http://localhost:3001/learning")
    except Exception as e:
        print(f"  could not start retrain ({e}); click 'Retrain now' on the Learning page.")


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in (*MODES, "demo", "calibrate"):
        print(__doc__)
        sys.exit(1)
    mode = sys.argv[1]
    try:
        if mode == "demo":
            run_demo()
        elif mode == "calibrate":
            run_calibrate()
        else:
            MODES[mode]()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
