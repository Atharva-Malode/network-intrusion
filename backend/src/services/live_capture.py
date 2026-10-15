"""
Live-sensor ground truth: calibration recording + the real-time confusion matrix.

The attack-script lab generator tags every request with X-Sim-Scenario (the
capture proxy forwards it as meta["scenario"]). That tag is ground truth for
evaluation only - it is never passed to the model. Two things use it:

  1. Calibration recording - every tagged record of a KNOWN class is appended to
     nids-model/data/live_capture.csv (capped per class). train.py folds these
     real sensor records into training (and holds the latest 30% of each class
     out as the "live holdout" test set), so the model learns what this sensor
     really emits for this site instead of a hand-written guess of it. The
     `novel` scenario is never recorded: the system has to discover it itself.

  2. Real-time confusion matrix - every tagged verdict the backend produces is
     tallied as (expected class, live verdict). This is the model's report card
     on the traffic it is classifying right now, not a replayed benchmark. It is
     snapshotted and reset whenever a new model is loaded, so the Learning page
     can show the previous model next to the current one.
"""

from __future__ import annotations

import csv
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.services.nids_engine import CLASS_ORDER, FEATURE_COLUMNS

_ROOT = Path(__file__).resolve().parents[3]
CAPTURE_CSV = _ROOT / "nids-model" / "data" / "live_capture.csv"

# Scenario tag -> the class a correct detector should report.
SCENARIO_CLASS = {
    "normal": "Normal",
    "recon": "Probe",
    "flood": "DoS",
    "credential": "R2L",
    "exploit": "U2R",
}
NOVEL_SCENARIO = "novel"
NOVEL_LABEL = "Novel"  # what the live matrix calls an event flagged as novel

# Rows kept per class in the calibration recording (oldest are kept; a fresh
# calibration should start from a deleted file - see reset_capture()).
MAX_ROWS_PER_CLASS = 4000

_lock = threading.Lock()
_counts: Counter = Counter()
_counts_loaded = False

# Learned class the novel scenario maps to once the system has learned it
# (e.g. "Attack-1"); None until then.
_novel_learned_as: Optional[str] = None

_matrix: Counter = Counter()          # (expected, predicted) -> n, current model
_matrix_started = time.time()
_previous: Optional[Dict[str, Any]] = None  # snapshot of the previous model's matrix


# --------------------------------------------------------------------------- #
# calibration recording
# --------------------------------------------------------------------------- #
def _load_counts() -> None:
    global _counts_loaded
    if _counts_loaded:
        return
    _counts_loaded = True
    if not CAPTURE_CSV.exists():
        return
    try:
        with CAPTURE_CSV.open(newline="") as fh:
            for r in csv.DictReader(fh):
                _counts[r["label"]] += 1
    except Exception:  # noqa: BLE001 - a bad file just means "start counting at 0"
        _counts.clear()


def record(features: Dict[str, Any], scenario: str) -> None:
    """Append one tagged sensor record of a known class to the calibration file."""
    label = SCENARIO_CLASS.get(scenario)
    if label is None:
        return
    with _lock:
        _load_counts()
        if _counts[label] >= MAX_ROWS_PER_CLASS:
            return
        CAPTURE_CSV.parent.mkdir(parents=True, exist_ok=True)
        new_file = not CAPTURE_CSV.exists()
        with CAPTURE_CSV.open("a", newline="") as fh:
            w = csv.writer(fh)
            if new_file:
                w.writerow(FEATURE_COLUMNS + ["label", "ts"])
            w.writerow([features.get(c, 0) for c in FEATURE_COLUMNS] + [label, round(time.time(), 3)])
        _counts[label] += 1


def capture_status() -> Dict[str, Any]:
    with _lock:
        _load_counts()
        return {
            "file": str(CAPTURE_CSV),
            "counts": {c: _counts.get(c, 0) for c in CLASS_ORDER},
            "max_per_class": MAX_ROWS_PER_CLASS,
        }


def reset_capture() -> Dict[str, Any]:
    with _lock:
        if CAPTURE_CSV.exists():
            CAPTURE_CSV.unlink()
        _counts.clear()
    return capture_status()


# --------------------------------------------------------------------------- #
# real-time confusion matrix
# --------------------------------------------------------------------------- #
def set_novel_learned_as(label: Optional[str]) -> None:
    global _novel_learned_as
    _novel_learned_as = label


def expected_for(scenario: str) -> Optional[str]:
    if scenario in SCENARIO_CLASS:
        return SCENARIO_CLASS[scenario]
    if scenario == NOVEL_SCENARIO:
        return _novel_learned_as or NOVEL_LABEL
    return None


def tally(scenario: str, detection: Dict[str, Any]) -> None:
    expected = expected_for(scenario)
    if expected is None:
        return
    predicted = NOVEL_LABEL if detection.get("novel") else str(detection.get("label", "Unknown"))
    with _lock:
        _matrix[(expected, predicted)] += 1


def _matrix_dict(counter: Counter, started: float) -> Dict[str, Any]:
    present = {e for e, _ in counter} | {p for _, p in counter}
    base = [c for c in CLASS_ORDER if c in present]
    extra = sorted(present - set(CLASS_ORDER) - {NOVEL_LABEL, "Unknown"})
    tail = [c for c in (NOVEL_LABEL, "Unknown") if c in present]
    labels = base + extra + tail
    matrix = [[counter.get((e, p), 0) for p in labels] for e in labels]
    total = sum(counter.values())
    correct = sum(counter.get((c, c), 0) for c in labels)
    return {
        "labels": labels,
        "matrix": matrix,
        "total": total,
        "accuracy": round(correct / total, 4) if total else None,
        "since": started,
    }


def live_matrix() -> Dict[str, Any]:
    with _lock:
        return {
            "current": _matrix_dict(_matrix, _matrix_started),
            "previous": _previous,
            "novel_learned_as": _novel_learned_as,
        }


def roll_matrix() -> None:
    """A new model was loaded: keep the old model's matrix as `previous`."""
    global _previous, _matrix_started
    with _lock:
        if sum(_matrix.values()):
            _previous = _matrix_dict(_matrix, _matrix_started)
        _matrix.clear()
        _matrix_started = time.time()


def reset_matrix() -> None:
    global _previous, _matrix_started
    with _lock:
        _matrix.clear()
        _previous = None
        _matrix_started = time.time()
