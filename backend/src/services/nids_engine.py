"""
NIDS inference engine (backend side).

Loads the pretrained NSL-KDD RandomForest pipeline (trained by ../nids-model)
and classifies incoming connection feature records into one of:
    Normal / DoS / Probe / R2L / U2R

The model artifact is a self-contained sklearn Pipeline (one-hot + RF). We keep
a local copy of the feature-column order and class metadata so the backend does
not need to import the sibling nids-model project (source of truth for these
lists is nids-model/nsl_kdd.py).
"""

from __future__ import annotations

import os
import sys
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

import pandas as pd

# --- NSL-KDD schema (mirror of nids-model/nsl_kdd.py) ---
FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]
CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]
CLASS_ORDER = ["Normal", "DoS", "Probe", "R2L", "U2R"]
CLASS_DESCRIPTIONS = {
    "Normal": "Legitimate traffic - no intrusion signature.",
    "DoS": "Denial of Service - flooding / resource exhaustion.",
    "Probe": "Reconnaissance - scanning, enumeration, fingerprinting.",
    "R2L": "Remote-to-Local - unauthorized remote access (credential / auth abuse).",
    "U2R": "User-to-Root - privilege escalation / remote code execution.",
}

_DEFAULTS: Dict[str, Any] = {c: 0 for c in FEATURE_COLUMNS}
_DEFAULTS.update({"protocol_type": "tcp", "service": "http", "flag": "SF"})

_model = None
_model_load_error: Optional[str] = None
_novelty: Optional[Dict[str, Any]] = None  # {"scaler", "nn", "columns", "threshold"}


def _model_path() -> Path:
    env = os.environ.get("NIDS_MODEL_PATH")
    if env:
        return Path(env)
    # backend/src/services/ -> repo root -> nids-model/artifacts/model.joblib
    root = Path(__file__).resolve().parents[3]
    return root / "nids-model" / "artifacts" / "model.joblib"


def _ensure_nids_model_importable() -> None:
    """The fitted Pipeline pickles a FunctionTransformer referencing
    `features.engineer_features` (see nids-model/features.py). Put the
    nids-model dir on sys.path so joblib.load can resolve that module here."""
    nids_dir = Path(__file__).resolve().parents[3] / "nids-model"
    p = str(nids_dir)
    if nids_dir.exists() and p not in sys.path:
        sys.path.insert(0, p)


def load_model():
    global _model, _model_load_error, _novelty
    if _model is not None:
        return _model
    try:
        import joblib  # imported lazily so backend still boots without it
        path = _model_path()
        if not path.exists():
            _model_load_error = f"model artifact not found at {path} (run nids-model/train.py)"
            return None
        _ensure_nids_model_importable()
        _model = joblib.load(path)
        # One row per call: joblib's thread fan-out costs more than it saves.
        clf = getattr(_model, "named_steps", {}).get("clf")
        if clf is not None and hasattr(clf, "n_jobs"):
            clf.n_jobs = 1
        _model_load_error = None
        print(f"[NIDS] loaded model from {path}", file=sys.stderr)
        nov_path = path.parent / "novelty.joblib"
        _novelty = joblib.load(nov_path) if nov_path.exists() else None
        if _novelty:
            print(f"[NIDS] loaded novelty detector from {nov_path}", file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        _model_load_error = f"failed to load model: {e}"
        print(f"[NIDS] {_model_load_error}", file=sys.stderr)
    return _model


def reload_model():
    """Force the next classify() to reload the model artifact from disk
    (used after a retrain)."""
    global _model, _model_load_error, _novelty
    _model = None
    _novelty = None
    _model_load_error = None
    return load_model()


def model_classes() -> List[str]:
    m = load_model()
    return [str(c) for c in m.classes_] if m is not None else list(CLASS_ORDER)


def model_status() -> Dict[str, Any]:
    m = load_model()
    return {
        "loaded": m is not None,
        "path": str(_model_path()),
        "error": _model_load_error,
        "classes": model_classes(),
        "novelty_detector": _novelty is not None,
    }


def _novelty_check(X: pd.DataFrame) -> Dict[str, Any]:
    """Open-set check: is this record unlike anything the sensor-domain training
    data contains? Nearest-neighbour distance (robust-scaled) to the live-sensor
    rows of every class the model knows, including learned ones - fitted by
    nids-model/train.py. novelty_score is that distance / the threshold, so
    > 1.0 means "farther from known traffic than known traffic ever is"."""
    if not _novelty or "nn" not in _novelty:
        return {"outlier": False, "novelty_score": None}
    import numpy as np
    from features import engineer_features  # on sys.path via _ensure_nids_model_importable
    Z = engineer_features(X)[_novelty["columns"]].astype(float).to_numpy()
    A = np.nan_to_num(_novelty["scaler"].transform(Z))
    dist = float(_novelty["nn"].kneighbors(A, n_neighbors=1)[0][0, 0])
    ratio = dist / _novelty["threshold"] if _novelty["threshold"] > 0 else 0.0
    return {"outlier": ratio > 1.0, "novelty_score": round(ratio, 3)}


# Volumetric-DoS signature: sustained request rate to the same service within
# the sensor's 2s window. The ML model keys on DoS *shape* (errors/zero-bytes);
# this complements it by catching high-rate floods the origin absorbs cleanly.
DOS_COUNT_THRESHOLD = 20

# Novelty thresholds: the model is "unsure" if its top class probability is below
# CONF_THRESHOLD, or the margin between the top two classes is below MARGIN.
CONF_THRESHOLD = 0.70
MARGIN_THRESHOLD = 0.20


def _ml_classify(features: Dict[str, Any]) -> Dict[str, Any]:
    """Pure model prediction (the primary engine)."""
    m = load_model()
    if m is None:
        return {
            "label": "Unknown",
            "confidence": 0.0,
            "probabilities": {},
            "description": "Model not loaded - train nids-model first.",
            "model_loaded": False,
        }

    row = dict(_DEFAULTS)
    for k, v in features.items():
        if k in row and v is not None:
            row[k] = v

    X = pd.DataFrame([[row[c] for c in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
    for c in CATEGORICAL_COLUMNS:
        X[c] = X[c].astype(str)

    novelty = _novelty_check(X)
    classes = list(m.classes_)
    if hasattr(m, "predict_proba"):
        proba = m.predict_proba(X)[0]
        probs = {cls: round(float(p), 4) for cls, p in zip(classes, proba)}
        top = int(proba.argmax())
        label = str(classes[top])
        confidence = round(float(proba[top]), 4)
    else:
        label = str(m.predict(X)[0])
        probs = {label: 1.0}
        confidence = 1.0

    return {
        "label": label,
        "confidence": confidence,
        "probabilities": probs,
        "description": CLASS_DESCRIPTIONS.get(label, _learned_description(label)),
        "model_loaded": True,
        **novelty,
    }


def _learned_description(label: str) -> str:
    return f"Learned attack class '{label}' - taught live from captured novel traffic."


# Probe backstop: a sustained multi-endpoint 4xx storm (scanner enumerating many
# distinct services). Tight enough that a stray 404 from a real user (count~1)
# never trips it, and DoS can't (a flood pins same_srv~1 -> diff_srv~0).
PROBE_COUNT_THRESHOLD = 8
PROBE_RERROR_MIN = 0.5
PROBE_DIFF_SRV_MIN = 0.5


def _signature_scan(features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Transparent signature tier keyed on the same sensor features as the model.
    Two precedence tiers, both fully attributed via source="signature":

      * content tier (HIGH precision) — R2L (failed auth) and U2R (RCE/traversal
        tokens). These key on unambiguous request *content*, so they OVERRIDE a
        model call that is only a traffic-*shape* class (Normal/Probe/DoS): a
        request carrying an RCE token is U2R even inside a high-count window the
        model reads as DoS.
      * shape tier (BACKSTOP) — Probe (4xx enumeration storm) and volumetric DoS.
        These only promote when the model itself did not land a positive attack,
        so the (now sensor-trained) model stays the primary voice for them.
    """
    root_shell = int(features.get("root_shell", 0) or 0)
    num_shells = int(features.get("num_shells", 0) or 0)
    num_root = int(features.get("num_root", 0) or 0)
    hot = int(features.get("hot", 0) or 0)
    failed = int(features.get("num_failed_logins", 0) or 0)
    count = int(features.get("count", 0) or 0)
    same_srv = float(features.get("same_srv_rate", 0.0) or 0.0)
    diff_srv = float(features.get("diff_srv_rate", 0.0) or 0.0)
    rerror = float(features.get("rerror_rate", 0.0) or 0.0)

    # --- content tier (high precision, overrides a shape-class model call) ---
    # U2R: RCE / traversal / sensitive-file execution indicators.
    if root_shell or num_shells or num_root:
        strength = min(0.98, 0.70 + 0.08 * (root_shell + num_shells + num_root))
        return {
            "label": "U2R", "tier": "content", "confidence": round(strength, 2),
            "reason": f"RCE/traversal indicators (root_shell={root_shell}, num_root={num_root}, hot={hot})",
        }
    # R2L: failed authentication against a protected endpoint.
    if failed >= 1:
        return {
            "label": "R2L", "tier": "content", "confidence": 0.85,
            "reason": f"failed auth on protected endpoint (num_failed_logins={failed})",
        }
    # --- shape tier (backstop, only when the model didn't call an attack) ---
    # Probe: sustained enumeration of many distinct endpoints, mostly 4xx.
    if (count >= PROBE_COUNT_THRESHOLD and rerror >= PROBE_RERROR_MIN
            and diff_srv >= PROBE_DIFF_SRV_MIN):
        return {
            "label": "Probe", "tier": "shape",
            "confidence": round(min(0.95, 0.60 + rerror * 0.3), 2),
            "reason": f"endpoint enumeration (count={count}/2s, rerror_rate={rerror}, diff_srv_rate={diff_srv})",
        }
    # Volumetric DoS backstop: sustained high rate to one service.
    if count >= DOS_COUNT_THRESHOLD and same_srv >= 0.5:
        return {
            "label": "DoS", "tier": "shape",
            "confidence": round(min(0.95, 0.60 + count / 1000.0), 2),
            "reason": f"volumetric flood (count={count}/2s, same_srv_rate={same_srv})",
        }
    return None


# Traffic-shape classes: a model call of one of these is a shape guess that a
# high-precision content signature is allowed to override.
_SHAPE_LABELS = ("Normal", "Unknown", "Probe", "DoS")


def classify(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Two-tier verdict: ML model (primary) + signature tier. With the sensor-shape
    trained model the model owns all five classes; signatures add defense in
    depth: content signatures (R2L/U2R) override a shape-class model guess, and
    the shape backstops (Probe/DoS) only promote when the model returned
    Normal/Unknown. Fully attributed via `source` and `signature`.
    """
    ml = _ml_classify(features)
    sig = _signature_scan(features)

    result = dict(ml)
    result["source"] = "model"
    result["model_label"] = ml["label"]
    result["model_confidence"] = ml["confidence"]
    result["signature"] = {"matched": bool(sig)}

    if sig:
        result["signature"] = {"matched": True, **sig}
        tier = sig.get("tier")
        # content tier overrides a shape-class model call; shape tier only
        # promotes when the model didn't already land a positive attack.
        promote = (ml["label"] in _SHAPE_LABELS) if tier == "content" \
            else (ml["label"] in ("Normal", "Unknown"))
        if promote:
            result["label"] = sig["label"]
            result["confidence"] = sig["confidence"]
            result["source"] = "signature"
            result["description"] = CLASS_DESCRIPTIONS.get(sig["label"], "")
            result["outlier"] = False  # a known signature explains it

    # Novelty: the model is unsure (low top-prob or classes competing) and no
    # signature rescued it -> candidate for a possibly-new attack type.
    probs = ml.get("probabilities") or {}
    ordered = sorted(probs.values(), reverse=True) if probs else [1.0]
    p1 = ordered[0]
    p2 = ordered[1] if len(ordered) > 1 else 0.0
    model_unsure = ml.get("model_loaded") and (p1 < CONF_THRESHOLD or (p1 - p2) < MARGIN_THRESHOLD)
    result["uncertain"] = bool(model_unsure)
    # Novel = the record is an outlier to everything the model was trained on
    # (open-set detector), no signature explains it, and the model did not land
    # a confident known attack. Normal browsing is an inlier, so it can never
    # leak into the novel bucket.
    result["novel"] = bool(
        result.get("outlier")
        and not sig
        and (model_unsure or ml["label"] in ("Normal", "Unknown"))
    )

    return result


# --- rolling threat summary for the dashboard ---
_recent: Deque[Dict[str, Any]] = deque(maxlen=500)


def record_detection(detection: Dict[str, Any], meta: Dict[str, Any]) -> None:
    _recent.append({
        "ts": time.time(),
        "label": detection.get("label", "Unknown"),
        "confidence": detection.get("confidence", 0.0),
        "src_ip": meta.get("src_ip", ""),
        "path": meta.get("path", ""),
    })


def threat_summary() -> Dict[str, Any]:
    items = list(_recent)
    total = len(items)
    class_counts = Counter(i["label"] for i in items)
    attack_items = [i for i in items if i["label"] not in ("Normal", "Unknown")]
    attack_count = len(attack_items)

    # Dominant active attack class (excluding Normal) in the recent window.
    dominant = None
    if attack_items:
        dominant = Counter(i["label"] for i in attack_items).most_common(1)[0][0]

    top_ips = Counter(i["src_ip"] for i in attack_items).most_common(5)

    return {
        "window_size": total,
        "attack_count": attack_count,
        "attack_ratio": round(attack_count / total, 3) if total else 0.0,
        "dominant_attack": dominant,
        "class_counts": {
            **{c: class_counts.get(c, 0) for c in CLASS_ORDER},
            # learned classes (e.g. Attack-1) seen in the window
            **{c: n for c, n in class_counts.items() if c not in CLASS_ORDER and c != "Unknown"},
        },
        "top_attacker_ips": [{"ip": ip, "count": n} for ip, n in top_ips],
    }


def features_from_event(event) -> Dict[str, Any]:
    """
    Best-effort feature record from a simulator TrafficEvent (used so the
    dashboard 'simulate' buttons also exercise the model). The proxy sensor is
    the authoritative feature source for real traffic.
    """
    path = (event.path or "").lower()
    is_attack_path = any(k in path for k in ["admin", "env", "debug", "bypass", "exec", "cmd", "phpmyadmin", "config", "cgi-bin", "passwd"])
    is_auth = any(k in path for k in ["login", "auth", "bypass", "session"])
    rce = 1 if any(k in path for k in ["exec", "cmd", "cgi-bin", "passwd", "shell", "../"]) else 0

    return {
        "protocol_type": "tcp",
        "service": "http",
        "flag": "REJ" if is_attack_path else "SF",
        "src_bytes": int(getattr(event, "content_length", 0) or 0),
        "dst_bytes": 0,
        "duration": 0.0,
        "hot": 2 if is_attack_path else 0,
        "num_failed_logins": 1 if is_auth else 0,
        "root_shell": rce,
        "num_shells": rce,
        "num_root": rce,
        "num_access_files": 1 if is_attack_path else 0,
        "count": 1,
        "srv_count": 1,
        "rerror_rate": 1.0 if is_attack_path else 0.0,
        "diff_srv_rate": 0.8 if is_attack_path else 0.0,
        "same_srv_rate": 0.2 if is_attack_path else 1.0,
        "dst_host_count": 1,
        "dst_host_srv_count": 1,
        "dst_host_rerror_rate": 1.0 if is_attack_path else 0.0,
        "dst_host_diff_srv_rate": 0.8 if is_attack_path else 0.0,
    }
