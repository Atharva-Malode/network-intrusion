"""
Active-learning engine: capture novel/uncertain events, let a human name them,
synthesize similar samples, and retrain the model to learn the new class.

Flow:
  0. auto-learn       - with auto-learn on (off by default) steps 2+3 run by themselves as
                        soon as AUTO_LEARN_MIN novel events are in the bucket: the
                        bucket is named "Attack-N" and the model retrains on it.
  1. add_candidate()  - ingest route feeds novel events here (bucket "Attack-N")
  2. label_bucket()   - user names the bucket -> synthesize samples -> append to
                        nids-model/data/custom_labeled.csv, clear bucket
  3. start_retrain()  - retrains the model (NSL-KDD + custom_labeled.csv) in the
                        background; hot-reloads the model on success. Given a
                        name, it first runs label_bucket(name) (Learning page:
                        type a class name, click Retrain).
  4. status()         - everything the dashboard needs (pending, classes, metrics,
                        retrain state)
"""

from __future__ import annotations

import csv
import json
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from src.services import live_capture, nids_engine
from src.services.nids_engine import FEATURE_COLUMNS, CATEGORICAL_COLUMNS

_ROOT = Path(__file__).resolve().parents[3]
_NIDS_DIR = _ROOT / "nids-model"
_DATA_DIR = _NIDS_DIR / "data"
_ARTIFACTS = _NIDS_DIR / "artifacts"
_CUSTOM_CSV = _DATA_DIR / "custom_labeled.csv"
_MODEL = _ARTIFACTS / "model.joblib"
_MODEL_BACKUP = _ARTIFACTS / "model_prev.joblib"
_NOVELTY = _ARTIFACTS / "novelty.joblib"
_NOVELTY_BACKUP = _ARTIFACTS / "novelty_prev.joblib"
# name -> {"scenario": majority ground-truth tag of its captured events, ...}
_LEARNED_JSON = _DATA_DIR / "learned_classes.json"

# A retrain is accepted only if the new model does not regress quality by more
# than this margin. macro-F1 is the primary guard (it weights the rare classes
# equally); accuracy is the secondary guard. If the new model is worse on both
# beyond the margin, we roll back to the previous model and ask for a human.
_QUALITY_MARGIN = 0.02

# Rate features are bounded to [0, 1]; the rest are non-negative counts.
_RATE_COLS = {c for c in FEATURE_COLUMNS if c.endswith("_rate")}
_NUMERIC_COLS = [c for c in FEATURE_COLUMNS if c not in CATEGORICAL_COLUMNS]

# How many synthetic rows to synthesize per labeling action (spread across the
# captured candidates).
SYNTH_TARGET = 600

# Auto-learn: if enabled, once this many novel events are in the bucket it is
# named "Attack-N", synthesized, and retrained WITHOUT a click. OFF by default
# (see _auto below) — training only happens on an explicit action: the user
# clicks "Retrain now" on the Learning page, or runs `main.py calibrate`. Toggle
# via POST /learning/auto.
AUTO_LEARN_MIN = 30

# The bucket holds ONE continuous burst of unknown traffic: a gap longer than
# this restarts it, so stray outliers from earlier attack phases (a few flood or
# scan requests the model let through as Normal) are not learned into the new
# class along with the attack the user is naming.
BURST_GAP_SECONDS = 20.0
_auto = {"enabled": False, "last": None}

_lock = threading.Lock()
_pending: List[Dict[str, Any]] = []
_bucket_id = 1
_label_awaiting_retrain: Optional[str] = None


def _read_learned() -> Dict[str, Any]:
    try:
        return json.loads(_LEARNED_JSON.read_text())
    except Exception:  # noqa: BLE001
        return {}


def _restore_state() -> None:
    """On backend start: continue bucket numbering after already-learned classes
    and remember which learned class the novel lab scenario maps to (scoring)."""
    global _bucket_id
    learned = _read_learned()
    known = set(nids_engine.model_classes())
    for name, info in learned.items():
        if name.startswith("Attack-") and name[7:].isdigit():
            _bucket_id = max(_bucket_id, int(name[7:]) + 1)
        if info.get("scenario") == live_capture.NOVEL_SCENARIO and name in known:
            live_capture.set_novel_learned_as(name)
_retrain: Dict[str, Any] = {
    "state": "idle", "message": "", "started": None, "finished": None,
    "human_intervention": False, "note": "", "quality": None,
    "label": None, "summary": None,
}


# --------------------------------------------------------------------------- #
# candidate capture
# --------------------------------------------------------------------------- #
def current_bucket_name() -> str:
    return f"Attack-{_bucket_id}"


def add_candidate(features: Dict[str, Any], meta: Dict[str, Any], detection: Dict[str, Any]) -> None:
    """Store a novel event in the pending bucket (and auto-learn when full)."""
    trigger = False
    with _lock:
        # Events seen while a retrain is running were judged by the outgoing
        # model; the bucket restarts once the new model is serving.
        if _retrain["state"] == "running" or _label_awaiting_retrain:
            return
        now = time.time()
        if _pending and now - _pending[-1]["ts"] > BURST_GAP_SECONDS:
            _pending.clear()
        _pending.append({
            "ts": now,
            "features": {k: features.get(k) for k in FEATURE_COLUMNS},
            "src_ip": meta.get("src_ip", ""),
            "path": meta.get("path", ""),
            "model_label": detection.get("model_label", detection.get("label")),
            "confidence": detection.get("confidence", 0.0),
            # Ground-truth tag, kept ONLY to report which lab scenario a learned
            # class came from. Not used for labelling or training.
            "scenario": str(meta.get("scenario") or ""),
        })
        # Keep the pending bucket bounded.
        if len(_pending) > 2000:
            del _pending[:-2000]
        trigger = _auto["enabled"] and len(_pending) >= AUTO_LEARN_MIN
    if trigger:
        threading.Thread(target=_auto_learn, daemon=True).start()


def _auto_learn() -> None:
    name = current_bucket_name()
    res = label_bucket(name)
    if res.get("status") != "labeled":
        return
    _auto["last"] = {"label": name, "rows": res["synthetic_rows"], "at": time.time()}
    start_retrain()


def set_auto_learn(enabled: bool) -> Dict[str, Any]:
    _auto["enabled"] = bool(enabled)
    return auto_status()


def auto_status() -> Dict[str, Any]:
    return {"enabled": _auto["enabled"], "min_events": AUTO_LEARN_MIN, "last": _auto["last"]}


def pending_summary(limit: int = 8) -> Dict[str, Any]:
    with _lock:
        recent = _pending[-limit:][::-1]
        return {
            "bucket_name": current_bucket_name(),
            "pending_count": len(_pending),
            "samples": [
                {
                    "src_ip": c["src_ip"],
                    "path": c["path"],
                    "model_guess": c["model_label"],
                    "confidence": c["confidence"],
                }
                for c in recent
            ],
        }


# --------------------------------------------------------------------------- #
# synthetic generation + labeling
# --------------------------------------------------------------------------- #
def _synthesize(candidates: List[Dict[str, Any]], target: int) -> List[Dict[str, Any]]:
    """Gaussian-jitter synthetic rows around the captured candidate vectors.

    Each row carries `group` = the index of the captured event it was grown
    from, so train.py can hold out whole events (not near-copies of training
    rows) when it scores the learned class."""
    if not candidates:
        return []
    rng = np.random.default_rng(42)
    feats = [c["features"] for c in candidates]

    # Per-numeric-column std across candidates (fallback to a small fraction of
    # the value so a single candidate still produces variation).
    arr = {col: np.array([float(f.get(col) or 0.0) for f in feats]) for col in _NUMERIC_COLS}
    stds = {col: (float(arr[col].std()) if len(arr[col]) > 1 else 0.0) for col in _NUMERIC_COLS}

    rows: List[Dict[str, Any]] = []
    per = max(1, target // len(feats))
    for gi, f in enumerate(feats):
        # The captured event itself, then `per - 1` jittered neighbours.
        rows.append({**{c: f.get(c) for c in FEATURE_COLUMNS}, "group": gi})
        for _ in range(per - 1):
            row: Dict[str, Any] = {"group": gi}
            for col in CATEGORICAL_COLUMNS:
                row[col] = f.get(col) or ("tcp" if col == "protocol_type" else "http" if col == "service" else "SF")
            for col in _NUMERIC_COLS:
                base = float(f.get(col) or 0.0)
                sigma = stds[col] if stds[col] > 0 else abs(base) * 0.1
                val = base + rng.normal(0.0, sigma)
                if col in _RATE_COLS:
                    val = min(1.0, max(0.0, val))
                else:
                    val = max(0.0, val)
                    if abs(val - round(val)) < 0.5 and base == round(base):
                        val = float(round(val))
                row[col] = round(val, 4)
            rows.append(row)
    return rows


_CUSTOM_HEADER = FEATURE_COLUMNS + ["label", "group"]


def _ensure_custom_header() -> None:
    """Older custom_labeled.csv files have no `group` column; add one."""
    if not _CUSTOM_CSV.exists():
        return
    with _CUSTOM_CSV.open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    if rows and "group" in rows[0]:
        return
    with _CUSTOM_CSV.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=_CUSTOM_HEADER)
        w.writeheader()
        for i, r in enumerate(rows):
            w.writerow({**{c: r.get(c, 0) for c in FEATURE_COLUMNS},
                        "label": r.get("label", ""), "group": f"legacy-{i}"})


def label_bucket(name: str) -> Dict[str, Any]:
    """Name the pending bucket, synthesize samples, append to the custom dataset."""
    global _bucket_id, _label_awaiting_retrain
    name = (name or "").strip() or current_bucket_name()
    with _lock:
        candidates = list(_pending)
        if not candidates:
            return {"status": "empty", "message": "No pending novel events to label."}

        synth = _synthesize(candidates, SYNTH_TARGET)

        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        _ensure_custom_header()
        write_header = not _CUSTOM_CSV.exists()
        with _CUSTOM_CSV.open("a", newline="") as fh:
            writer = csv.writer(fh)
            if write_header:
                writer.writerow(_CUSTOM_HEADER)
            for row in synth:
                writer.writerow([row.get(c, 0) for c in FEATURE_COLUMNS]
                                + [name, f"{name}-{row['group']}"])

        scenarios = Counter(c["scenario"] for c in candidates if c["scenario"])
        learned = _read_learned()
        learned[name] = {
            "scenario": scenarios.most_common(1)[0][0] if scenarios else "",
            "captured_events": len(candidates),
            "synthetic_rows": len(synth),
            "labeled_at": time.time(),
        }
        _LEARNED_JSON.write_text(json.dumps(learned, indent=2))

        _pending.clear()
        _bucket_id += 1
        _label_awaiting_retrain = name

    return {
        "status": "labeled",
        "label": name,
        "synthetic_rows": len(synth),
        "custom_classes": custom_class_counts(),
    }


def custom_class_counts() -> Dict[str, int]:
    """Class -> row count in the custom labeled dataset."""
    if not _CUSTOM_CSV.exists():
        return {}
    counts: Counter = Counter()
    try:
        with _CUSTOM_CSV.open(newline="") as fh:
            reader = csv.DictReader(fh)
            for r in reader:
                counts[r["label"]] += 1
    except Exception:  # noqa: BLE001
        return {}
    return dict(counts)


# --------------------------------------------------------------------------- #
# metrics / model card
# --------------------------------------------------------------------------- #
def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text())
    except Exception:  # noqa: BLE001
        return None


def metrics() -> Dict[str, Any]:
    return {
        "current": _read_json(_ARTIFACTS / "metrics.json"),
        "previous": _read_json(_ARTIFACTS / "metrics_prev.json"),
    }


# --------------------------------------------------------------------------- #
# retrain
# --------------------------------------------------------------------------- #
def _quality(m: Optional[Dict[str, Any]]) -> Optional[Dict[str, float]]:
    """Extract the comparable quality numbers from a metrics dict."""
    if not m:
        return None
    return {
        "macro_f1": float(m.get("test_macro_f1", 0.0) or 0.0),
        "accuracy": float(m.get("test_accuracy", 0.0) or 0.0),
    }


def _retrain_worker() -> None:
    global _retrain
    try:
        # Snapshot the current (good) model so we can roll back if the retrain
        # produces a worse one. train.py itself snapshots metrics.json ->
        # metrics_prev.json before overwriting it, so after the run
        # metrics_prev.json = the pre-retrain metrics we compare against.
        had_backup = False
        if _MODEL.exists():
            shutil.copy2(_MODEL, _MODEL_BACKUP)
            had_backup = True
        had_novelty = _NOVELTY.exists()
        if had_novelty:
            shutil.copy2(_NOVELTY, _NOVELTY_BACKUP)

        proc = subprocess.run(
            [sys.executable, "train.py", "--with-custom"],
            cwd=str(_NIDS_DIR),
            capture_output=True,
            text=True,
            timeout=1800,
        )
        tail = (proc.stdout or "").strip().splitlines()[-8:]

        if proc.returncode != 0:
            # Training crashed: keep the existing model untouched, ask for a human.
            _retrain.update({
                "state": "error",
                "message": f"train.py exited {proc.returncode}; previous model kept.",
                "finished": time.time(),
                "human_intervention": True,
                "note": "Retraining failed to run. The previous model is still active. "
                        "Check the training logs below — human intervention needed.",
                "tail": (proc.stderr or proc.stdout or "").strip().splitlines()[-8:],
            })
            return

        new_q = _quality(_read_json(_ARTIFACTS / "metrics.json"))
        old_q = _quality(_read_json(_ARTIFACTS / "metrics_prev.json"))

        regressed = (
            new_q is not None and old_q is not None
            and new_q["macro_f1"] < old_q["macro_f1"] - _QUALITY_MARGIN
            and new_q["accuracy"] < old_q["accuracy"] - _QUALITY_MARGIN
        )

        if regressed and had_backup:
            # Roll back: restore the previous model artifacts and reload them.
            shutil.copy2(_MODEL_BACKUP, _MODEL)
            if had_novelty:
                shutil.copy2(_NOVELTY_BACKUP, _NOVELTY)
            nids_engine.reload_model()
            _retrain.update({
                "state": "review",
                "message": "New model was worse — rolled back to the previous model.",
                "finished": time.time(),
                "human_intervention": True,
                "note": (
                    f"⚠️ Human intervention needed. The retrained model regressed "
                    f"(macro-F1 {new_q['macro_f1']:.3f} vs {old_q['macro_f1']:.3f}, "
                    f"accuracy {new_q['accuracy']:.3f} vs {old_q['accuracy']:.3f}). "
                    f"The previous model was kept and is still serving. Review the new "
                    f"labels/data before retraining again."
                ),
                "quality": {"new": new_q, "previous": old_q, "accepted": False},
                "tail": tail,
            })
        else:
            # Accept the new model.
            nids_engine.reload_model()
            _on_new_model()
            _retrain.update({
                "state": "done",
                "message": "Retrain complete; new model accepted and reloaded.",
                "finished": time.time(),
                "human_intervention": False,
                "note": "",
                "quality": {"new": new_q, "previous": old_q, "accepted": True},
                "tail": tail,
            })
            _retrain["summary"] = _summary(_retrain.get("label"))
    except Exception as e:  # noqa: BLE001
        _retrain.update({
            "state": "error", "message": str(e), "finished": time.time(),
            "human_intervention": True,
            "note": "Retrain raised an exception; the previous model is still active.",
        })


def _retrain_finished() -> None:
    """Whatever the outcome, the labelled bucket is no longer waiting."""
    global _label_awaiting_retrain
    _label_awaiting_retrain = None


def _on_new_model() -> None:
    """A new model is serving: score it from a clean live matrix, map the novel
    lab scenario to the class it was learned as, and restart the bucket."""
    live_capture.roll_matrix()
    known = set(nids_engine.model_classes())
    for name, info in _read_learned().items():
        if info.get("scenario") == live_capture.NOVEL_SCENARIO and name in known:
            live_capture.set_novel_learned_as(name)
    with _lock:
        _pending.clear()


def _summary(label: Optional[str]) -> Dict[str, Any]:
    """Result card for the Learning page, read from the metrics train.py just
    wrote (every number is measured, none is set here)."""
    m = _read_json(_ARTIFACTS / "metrics.json") or {}
    holdout = m.get("live_holdout") or {}
    learned = _read_learned().get(label or "", {})
    new_class = (holdout.get("per_class") or {}).get(label or "")
    started, finished = _retrain.get("started"), _retrain.get("finished")
    return {
        "label": label,
        "reset": bool(_retrain.get("reset")),
        "classes": nids_engine.model_classes(),
        "captured_events": learned.get("captured_events"),
        "synthetic_rows": learned.get("synthetic_rows"),
        "train_rows": m.get("train_rows"),
        "benchmark_accuracy": m.get("test_accuracy"),
        "live_accuracy": holdout.get("accuracy"),
        "new_class": {
            "precision": new_class["precision"], "recall": new_class["recall"],
            "f1": new_class["f1-score"], "heldout_rows": new_class["support"],
        } if new_class else None,
        "seconds": round(finished - started, 1) if started and finished else None,
    }


def reset_to_base() -> Dict[str, Any]:
    """Forget every learned class and retrain on the 5 base classes only.

    The learned-class files are moved (not deleted) to data/last_reset/, which is
    overwritten by the next reset. The calibration recording is kept."""
    global _bucket_id, _label_awaiting_retrain
    with _lock:
        if _retrain["state"] == "running":
            return {"status": "already_running", "retrain": dict(_retrain)}
        backup = _DATA_DIR / "last_reset"
        backup.mkdir(parents=True, exist_ok=True)
        for f in (_CUSTOM_CSV, _LEARNED_JSON):
            if f.exists():
                shutil.move(str(f), str(backup / f.name))
        _pending.clear()
        _bucket_id = 1
        _label_awaiting_retrain = None
        _auto["last"] = None
    live_capture.set_novel_learned_as(None)
    return start_retrain(reset=True)


def start_retrain(name: Optional[str] = None, reset: bool = False) -> Dict[str, Any]:
    """Retrain; with a name, first label the pending novel bucket as that class."""
    label = None
    if name and name.strip():
        if name.strip().lower() in {c.lower() for c in nids_engine.CLASS_ORDER + ["Unknown"]}:
            return {"status": "invalid", "message": f"'{name.strip()}' is a built-in class; pick a new name."}
        if _retrain["state"] == "running":
            return {"status": "already_running", "retrain": dict(_retrain)}
        res = label_bucket(name)
        if res.get("status") != "labeled":
            return res
        label = res["label"]
    with _lock:
        if _retrain["state"] == "running":
            return {"status": "already_running", "retrain": dict(_retrain)}
        _retrain.update({
            "state": "running", "message": "Retraining…", "started": time.time(),
            "finished": None, "human_intervention": False, "note": "", "quality": None,
            "label": label or _label_awaiting_retrain, "summary": None, "reset": reset,
        })
    def _run() -> None:
        try:
            _retrain_worker()
        finally:
            _retrain_finished()
    threading.Thread(target=_run, daemon=True).start()
    return {"status": "started", "retrain": dict(_retrain)}


def status() -> Dict[str, Any]:
    return {
        "pending": pending_summary(),
        "custom_classes": custom_class_counts(),
        "learned": _read_learned(),
        "retrain": dict(_retrain),
        "metrics": metrics(),
        "model": nids_engine.model_status(),
        "auto_learn": auto_status(),
        "capture": live_capture.capture_status(),
        "live_matrix": live_capture.live_matrix(),
    }


_restore_state()
