"""
Feature engineering shared by training and live inference.

Kept in its own dependency-light module (numpy + pandas only) so the fitted
Pipeline can pickle a reference to `engineer_features` and reload it in BOTH the
nids-model project and the backend. The backend adds this directory to
sys.path before joblib.load (see backend/src/services/nids_engine.py), so the
FunctionTransformer inside model.joblib resolves this exact function.

The transforms:
  * log1p of the heavy-tailed byte/count features (their raw scale spans many
    orders of magnitude; log makes the split points that separate the classes
    far cleaner);
  * a `content_score` that sums the R2L/U2R "content" indicators (failed logins,
    hot, root_shell, num_root, shells, file creations, guest login, file access)
    — the single most useful engineered signal for the rare classes, which are
    defined by connection *content* rather than traffic shape.

engineer_features(df) is pure and stateless: same 41 input columns in, the same
columns plus the engineered ones out. Never rename or drop the originals — the
ColumnTransformer downstream selects both sets by name.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

# Heavy-tailed features that benefit from a log1p compression.
LOG_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "count", "srv_count",
    "dst_host_count", "dst_host_srv_count", "num_root", "num_compromised",
    "hot", "num_file_creations", "num_failed_logins",
]

# Content indicators summed into `content_score`.
_CONTENT_COLS = [
    "hot", "num_failed_logins", "root_shell", "num_root", "num_shells",
    "num_file_creations", "is_guest_login", "num_access_files",
]

# Names of the columns this module ADDS, in a stable order.
ENGINEERED_COLUMNS = [f"log_{c}" for c in LOG_FEATURES] + ["content_score"]


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy of df with the engineered columns appended.

    Pure/stateless so it is safe inside a scikit-learn FunctionTransformer that
    gets pickled into the model artifact.
    """
    out = df.copy()
    for c in LOG_FEATURES:
        col = out[c] if c in out.columns else 0.0
        out[f"log_{c}"] = np.log1p(pd.to_numeric(col, errors="coerce").fillna(0.0).clip(lower=0))
    content = np.zeros(len(out), dtype=float)
    for c in _CONTENT_COLS:
        if c in out.columns:
            content = content + pd.to_numeric(out[c], errors="coerce").fillna(0.0).to_numpy()
    out["content_score"] = content
    return out
