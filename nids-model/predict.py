"""
Inference wrapper around the trained NSL-KDD pipeline.

Loads artifacts/model.joblib once and classifies a single connection given as a
dict of NSL-KDD feature values. Missing features are filled with safe defaults
(0 for numerics, "other"/"OTH" for categoricals) so the live sensor never has to
supply all 41 fields perfectly.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

import joblib
import pandas as pd

from nsl_kdd import CATEGORICAL_COLUMNS, CLASS_DESCRIPTIONS, FEATURE_COLUMNS

_DEFAULTS: Dict[str, Any] = {c: 0 for c in FEATURE_COLUMNS}
_DEFAULTS.update({"protocol_type": "tcp", "service": "http", "flag": "SF"})


def _model_path() -> Path:
    env = os.environ.get("NIDS_MODEL_PATH")
    if env:
        return Path(env)
    return Path(__file__).parent / "artifacts" / "model.joblib"


@lru_cache(maxsize=1)
def _load_model():
    path = _model_path()
    if not path.exists():
        raise FileNotFoundError(
            f"Model artifact not found at {path}. Run `python train.py` first."
        )
    return joblib.load(path)


def model_available() -> bool:
    return _model_path().exists()


def classify(features: Dict[str, Any]) -> Dict[str, Any]:
    """Classify one connection.

    Returns {label, confidence, probabilities: {class: p, ...}}.
    """
    model = _load_model()

    row = dict(_DEFAULTS)
    for k, v in features.items():
        if k in row and v is not None:
            row[k] = v

    X = pd.DataFrame([[row[c] for c in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
    # Cast categoricals to str so OneHotEncoder matches training dtypes.
    for c in CATEGORICAL_COLUMNS:
        X[c] = X[c].astype(str)

    classes = list(model.classes_)
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[0]
        probs = {cls: round(float(p), 4) for cls, p in zip(classes, proba)}
        top_idx = int(proba.argmax())
        label = classes[top_idx]
        confidence = round(float(proba[top_idx]), 4)
    else:
        label = str(model.predict(X)[0])
        probs = {label: 1.0}
        confidence = 1.0

    return {
        "label": label,
        "confidence": confidence,
        "probabilities": probs,
        "description": CLASS_DESCRIPTIONS.get(label, ""),
    }


if __name__ == "__main__":
    # Smoke test with a synthetic "neptune"-like DoS connection.
    demo = {
        "protocol_type": "tcp", "service": "http", "flag": "S0",
        "src_bytes": 0, "dst_bytes": 0, "count": 255, "srv_count": 255,
        "serror_rate": 1.0, "srv_serror_rate": 1.0, "same_srv_rate": 1.0,
        "dst_host_count": 255, "dst_host_srv_count": 255,
        "dst_host_serror_rate": 1.0, "dst_host_srv_serror_rate": 1.0,
    }
    print(classify(demo))
