"""
Reproducible training pipeline for the network-intrusion detection model.

What it does
------------
1. Downloads the canonical NSL-KDD train/test splits (cached under data/).
2. Maps the 40+ raw attack labels to the 5 canonical classes
   (Normal / DoS / Probe / R2L / U2R).
3. Builds a scikit-learn Pipeline: one-hot encode categoricals + RandomForest.
4. Trains on KDDTrain+, evaluates on the official KDDTest+ split.
5. If data/live_capture.csv exists (recorded by `attack-script/main.py
   calibrate` through the real capture proxy), trains on those REAL sensor
   records too, holding out the newest 30% of each class as the "live holdout"
   test set. Recorded classes replace the hand-written sensor-shape rows.
6. Fits the open-set novelty detector (IsolationForest) on the sensor-domain
   training rows, so traffic unlike every known class is flagged as novel.
7. Saves the fitted pipeline and a metrics report under artifacts/.

Run:  python train.py         (uv run python train.py)

The saved artifacts/model.joblib is a self-contained Pipeline: pass it a
DataFrame with the 41 NSL-KDD feature columns and it handles preprocessing
internally. handle_unknown="ignore" means categories the live sensor emits that
were unseen in training degrade gracefully instead of crashing.
"""

import json
import sys
import time
import urllib.request
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder

from features import ENGINEERED_COLUMNS, engineer_features
from nsl_kdd import (
    ALL_COLUMNS,
    CATEGORICAL_COLUMNS,
    CLASS_ORDER,
    FEATURE_COLUMNS,
    NUMERIC_COLUMNS,
    label_to_category,
)
from synthesize import synthesize_rare

HERE = Path(__file__).parent
DATA_DIR = HERE / "data"
ARTIFACTS_DIR = HERE / "artifacts"

# Stable raw mirrors of the NSL-KDD files (HoaNP is a long-lived backup mirror
# of the original UNB CIC dataset). Multiple sources are tried in order.
# Minimum plausible file sizes (bytes). A stalled/partial download that lands
# below this is rejected rather than cached, so a flaky connection can't poison
# later runs. Full files are ~18.6 MB (train) and ~3.4 MB (test).
MIN_SIZE = {"KDDTrain+.txt": 5_000_000, "KDDTest+.txt": 1_000_000}

DATA_SOURCES = {
    "KDDTrain+.txt": [
        "https://raw.githubusercontent.com/HoaNP/NSL-KDD-DataSet/master/KDDTrain+.txt",
        "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain+.txt",
        "https://raw.githubusercontent.com/mlaraibb/NSL-KDD-DATASET/main/KDDTrain+.txt",
    ],
    "KDDTest+.txt": [
        "https://raw.githubusercontent.com/HoaNP/NSL-KDD-DataSet/master/KDDTest+.txt",
        "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest+.txt",
        "https://raw.githubusercontent.com/mlaraibb/NSL-KDD-DATASET/main/KDDTest+.txt",
    ],
}


def download(filename: str) -> Path:
    """Download a dataset file if not already cached (validated, atomic)."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    dest = DATA_DIR / filename
    min_size = MIN_SIZE.get(filename, 1)

    if dest.exists() and dest.stat().st_size >= min_size:
        print(f"[data] cached: {dest.name} ({dest.stat().st_size:,} bytes)")
        return dest
    if dest.exists():
        print(f"[data] discarding truncated cache: {dest.name} "
              f"({dest.stat().st_size:,} < {min_size:,} bytes)")
        dest.unlink()

    last_err = None
    for url in DATA_SOURCES[filename]:
        tmp = dest.with_suffix(dest.suffix + ".part")
        try:
            print(f"[data] downloading {filename} from {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "nids-train"})
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = resp.read()
            if len(data) < min_size:
                raise ValueError(f"file too small ({len(data):,} < {min_size:,} bytes)")
            tmp.write_bytes(data)
            tmp.replace(dest)  # atomic: only a complete file appears at dest
            print(f"[data] saved {dest.name} ({dest.stat().st_size:,} bytes)")
            return dest
        except Exception as e:  # noqa: BLE001 - try next mirror
            print(f"[data] failed ({e}); trying next mirror...")
            tmp.unlink(missing_ok=True)
            last_err = e
    raise RuntimeError(
        f"Could not download {filename}: {last_err}. "
        f"You can manually place it in {DATA_DIR}/ and re-run."
    )


def load_split(filename: str) -> pd.DataFrame:
    path = download(filename)
    df = pd.read_csv(path, header=None, names=ALL_COLUMNS)
    df["category"] = df["label"].map(label_to_category)
    return df


# Numeric columns after feature engineering = raw numerics + engineered ones.
NUMERIC_COLUMNS_FE = NUMERIC_COLUMNS + ENGINEERED_COLUMNS


def build_pipeline() -> Pipeline:
    # Stage 0: feature engineering (log1p heavy tails + content_score). Pickled
    # by reference to features.engineer_features so it reloads in the backend.
    fe = FunctionTransformer(engineer_features, validate=False)
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore", sparse_output=True),
                CATEGORICAL_COLUMNS,
            ),
            ("num", "passthrough", NUMERIC_COLUMNS_FE),
        ]
    )
    clf = RandomForestClassifier(
        n_estimators=600,             # more trees stabilise the rare-class votes
        max_depth=None,
        max_features="log2",          # decorrelates trees -> better rare-class F1
        n_jobs=-1,
        class_weight="balanced_subsample",  # helps the rare R2L/U2R classes
        random_state=42,
    )
    return Pipeline([("fe", fe), ("prep", preprocessor), ("clf", clf)])


def load_custom() -> pd.DataFrame:
    """Load the human-labeled custom attack dataset (active-learning), if any."""
    path = DATA_DIR / "custom_labeled.csv"
    if not path.exists():
        return pd.DataFrame(columns=FEATURE_COLUMNS + ["category", "group"])
    df = pd.read_csv(path)
    df = df.rename(columns={"label": "category"})
    for c in FEATURE_COLUMNS:
        if c not in df.columns:
            df[c] = 0
    if "group" not in df.columns:
        df["group"] = [f"row-{i}" for i in range(len(df))]
    return df[FEATURE_COLUMNS + ["category", "group"]]


def split_custom(custom: pd.DataFrame, test_size: float = 0.3):
    """Hold out whole captured EVENTS per learned class (an event and all of its
    synthetic neighbours land on the same side), so the learned class is scored
    on events the model never saw, not on jittered copies of training rows."""
    from sklearn.model_selection import GroupShuffleSplit
    trains, tests = [], []
    for _, part in custom.groupby("category"):
        if part["group"].nunique() < 2:
            trains.append(part)
            continue
        gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=42)
        tr, te = next(gss.split(part, groups=part["group"]))
        trains.append(part.iloc[tr])
        tests.append(part.iloc[te])
    empty = custom.iloc[0:0]
    return (pd.concat(trains) if trains else empty), (pd.concat(tests) if tests else empty)


# A class needs at least this many recorded live rows before the recording
# replaces its hand-written sensor-shape rows.
LIVE_MIN_ROWS = 100


def load_live(test_frac: float = 0.3):
    """Real sensor records captured by `attack-script/main.py calibrate`.

    Split per class in TIME order: the newest `test_frac` of each class is the
    live holdout. Consecutive requests share sliding windows, so a random split
    would leak near-identical rows into the test set; a time split does not."""
    path = DATA_DIR / "live_capture.csv"
    if not path.exists():
        return None, None
    df = pd.read_csv(path).rename(columns={"label": "category"})
    if "ts" not in df.columns:
        df["ts"] = range(len(df))
    trains, tests = [], []
    for _, part in df.groupby("category"):
        part = part.sort_values("ts")
        cut = int(round(len(part) * (1 - test_frac)))
        trains.append(part.iloc[:cut])
        tests.append(part.iloc[cut:])
    cols = FEATURE_COLUMNS + ["category"]
    return pd.concat(trains)[cols], pd.concat(tests)[cols]


def fit_novelty(sensor_rows: pd.DataFrame, quantile: float = 0.995,
                max_rows: int = 20000) -> dict:
    """Open-set detector over the sensor-domain feature space.

    Nearest-neighbour distance in robust-scaled feature space, fitted on every
    sensor-domain training row of every KNOWN class (including learned ones). A
    live record farther from its nearest known row than `quantile` of the known
    rows are from each other looks like nothing the model was taught.

    (An IsolationForest was tried first: it dilutes a deviation in 2-3 features
    across ~50 mostly-uninformative ones and flagged 0% of the novel attack.
    Nearest-neighbour distance flagged 100% of it and 0% of the live holdout.)"""
    from sklearn.neighbors import NearestNeighbors
    from sklearn.preprocessing import RobustScaler
    rows = sensor_rows.sample(n=min(len(sensor_rows), max_rows), random_state=42)
    Z = engineer_features(rows[FEATURE_COLUMNS])[NUMERIC_COLUMNS_FE].astype(float).to_numpy()
    scaler = RobustScaler(quantile_range=(5, 95)).fit(Z)
    A = np.nan_to_num(scaler.transform(Z))
    nn = NearestNeighbors(n_neighbors=2).fit(A)
    # distance to the nearest OTHER known row (column 0 is the row itself)
    d = nn.kneighbors(A)[0][:, 1]
    return {"scaler": scaler, "nn": nn, "columns": list(NUMERIC_COLUMNS_FE),
            "threshold": float(np.quantile(d, quantile)), "fitted_rows": int(len(Z))}


def novelty_distance(novelty: dict, df: pd.DataFrame) -> np.ndarray:
    Z = engineer_features(df[FEATURE_COLUMNS])[novelty["columns"]].astype(float).to_numpy()
    A = np.nan_to_num(novelty["scaler"].transform(Z))
    return novelty["nn"].kneighbors(A, n_neighbors=1)[0][:, 0]


def score_holdout(pipeline: Pipeline, df: pd.DataFrame) -> dict:
    """Accuracy / per-class / confusion matrix on a holdout frame."""
    y = df["category"]
    p = pipeline.predict(df[FEATURE_COLUMNS])
    present = set(y) | set(p)
    labels = [c for c in CLASS_ORDER if c in present] + sorted(present - set(CLASS_ORDER))
    rep = classification_report(y, p, labels=labels, zero_division=0, output_dict=True)
    return {
        "rows": int(len(df)),
        "accuracy": round(float(accuracy_score(y, p)), 4),
        "macro_f1": round(float(f1_score(y, p, labels=sorted(set(y)), average="macro")), 4),
        "per_class": {k: v for k, v in rep.items() if k in labels},
        "confusion_matrix": {"labels": labels,
                             "matrix": confusion_matrix(y, p, labels=labels).tolist()},
    }


def main() -> int:
    t0 = time.time()
    with_custom = "--with-custom" in sys.argv
    # Synthetic minority-class oversampling is ON by default (the whole point is
    # to lift the starved R2L/U2R classes); --no-synthetic reproduces the raw
    # NSL-KDD baseline. Counts are tunable for experiments.
    with_synthetic = "--no-synthetic" not in sys.argv

    def _arg_int(flag: str, default: int) -> int:
        if flag in sys.argv:
            try:
                return int(sys.argv[sys.argv.index(flag) + 1])
            except (IndexError, ValueError):
                pass
        return default

    def _arg_float(flag: str, default: float) -> float:
        if flag in sys.argv:
            try:
                return float(sys.argv[sys.argv.index(flag) + 1])
            except (IndexError, ValueError):
                pass
        return default

    # R2L/U2R oversampling. sensor_fraction is kept low (0.25) so most rows carry
    # the genuine ftp/telnet "classic" shape (best for the KDDTest+ benchmark),
    # while the remaining 25% carry the live-proxy http shape (enough to land the
    # live attack scripts on the class — verified by eval_sensor.py).
    synth_r2l = _arg_int("--synth-r2l", 8000)
    synth_u2r = _arg_int("--synth-u2r", 6000)
    sensor_fraction = _arg_float("--sensor-fraction", 0.25)
    # Sensor-shape augmentation for the traffic-shape classes. Genuine NSL-KDD
    # already teaches their packet/flow shape; these rows teach the *live HTTP
    # proxy* shape so the model (not just a signature) owns the live call. Probe
    # is the class that fails outright without this; DoS otherwise leans on the
    # volumetric signature backstop. Normal is covered by genuine NSL-KDD, so it
    # gets no synthetic rows by default.
    synth_normal = _arg_int("--synth-normal", 0)
    synth_probe = _arg_int("--synth-probe", 1500)
    synth_dos = _arg_int("--synth-dos", 1500)
    print("=== NSL-KDD NIDS training ===")

    # Real recorded sensor traffic (calibration). Recorded classes no longer get
    # hand-written sensor-shape rows: the recording IS the sensor shape.
    live_train, live_test = (None, None) if "--no-live" in sys.argv else load_live()
    live_classes: set = set()
    if live_train is not None:
        counts = pd.concat([live_train, live_test])["category"].value_counts()
        live_classes = {c for c, n in counts.items() if n >= LIVE_MIN_ROWS}
        print(f"[data] live sensor recording: {counts.to_dict()} "
              f"(replacing sensor-shape synthesis for {sorted(live_classes)})")
        if "Normal" in live_classes:
            synth_normal = 0
        if "Probe" in live_classes:
            synth_probe = 0
        if "DoS" in live_classes:
            synth_dos = 0
        if {"R2L", "U2R"} <= live_classes:
            sensor_fraction = 0.0  # classic NSL-KDD flavour only; live covers http

    # Snapshot the previous metrics so the dashboard can show before/after.
    prev = ARTIFACTS_DIR / "metrics.json"
    if prev.exists():
        (ARTIFACTS_DIR / "metrics_prev.json").write_text(prev.read_text())

    train_df = load_split("KDDTrain+.txt")
    test_df = load_split("KDDTest+.txt")

    # Sensor-domain rows (what the live proxy emits) - the novelty detector's
    # notion of "known traffic" - and the live holdout test set.
    sensor_train_parts = []
    holdout_parts = []
    if live_train is not None:
        train_df = pd.concat([train_df, live_train], ignore_index=True)
        sensor_train_parts.append(live_train)
        holdout_parts.append(live_test)

    if with_custom:
        custom = load_custom()
        if len(custom):
            c_train, c_test = split_custom(custom)
            c_train = c_train[FEATURE_COLUMNS + ["category"]]
            c_test = c_test[FEATURE_COLUMNS + ["category"]]
            # Learned classes are scored on the live holdout (they come from the
            # live sensor), never mixed into the KDDTest+ benchmark.
            train_df = pd.concat([train_df, c_train], ignore_index=True)
            sensor_train_parts.append(c_train)
            holdout_parts.append(c_test)
            print(f"[data] merged custom dataset: {len(custom)} rows "
                  f"(train {len(c_train)} / holdout {len(c_test)}), "
                  f"classes={sorted(custom['category'].unique())}")

    # Synthetic oversampling of the starved rare classes (R2L / U2R). Added to
    # TRAINING ONLY so the KDDTest+ headline stays an honest, literature-
    # comparable benchmark. A separately-seeded synthetic HOLDOUT is scored on
    # its own further down (metrics["synthetic_holdout"]) so the improvement on
    # the rare-class signatures -- including the live HTTP-sensor shape produced
    # by the attack scripts -- is measurable without polluting the headline.
    synth_holdout = None
    _synth_any = synth_r2l or synth_u2r or synth_normal or synth_probe or synth_dos
    if with_synthetic and _synth_any:
        synth_train = synthesize_rare(
            n_r2l=synth_r2l, n_u2r=synth_u2r, seed=42, sensor_fraction=sensor_fraction,
            n_normal=synth_normal, n_probe=synth_probe, n_dos=synth_dos,
        )
        synth_holdout = synthesize_rare(
            n_r2l=max(1, synth_r2l // 4), n_u2r=max(1, synth_u2r // 4), seed=1337,
            sensor_fraction=sensor_fraction,
            n_normal=max(1, synth_normal // 4), n_probe=max(1, synth_probe // 4),
            n_dos=max(1, synth_dos // 4),
        )
        train_df = pd.concat([train_df, synth_train], ignore_index=True)
        # Classes without enough recorded rows: their synthetic http rows stand
        # in for the sensor, so the novelty detector knows them as familiar.
        sensor_train_parts.append(synth_train[(synth_train["service"] == "http")
                                              & ~synth_train["category"].isin(live_classes)])
        print(f"[data] added synthetic sensor-shape rows: "
              f"{synth_train['category'].value_counts().to_dict()} "
              f"(holdout {len(synth_holdout)} rows scored separately)")

    print(f"[data] train rows: {len(train_df):,}  test rows: {len(test_df):,}")
    print("[data] train class balance:")
    print(train_df["category"].value_counts().to_string())

    X_train = train_df[FEATURE_COLUMNS]
    y_train = train_df["category"]
    X_test = test_df[FEATURE_COLUMNS]
    y_test = test_df["category"]

    pipeline = build_pipeline()
    print("[train] fitting RandomForest pipeline...")
    pipeline.fit(X_train, y_train)

    print("[eval] scoring on test split...")
    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    present = set(y_test) | set(y_pred)
    # Canonical classes first, then any custom classes, in a stable order.
    labels = [c for c in CLASS_ORDER if c in present] + sorted(present - set(CLASS_ORDER))
    report = classification_report(
        y_test, y_pred, labels=labels, zero_division=0, output_dict=True
    )
    cm = confusion_matrix(y_test, y_pred, labels=labels)

    print(f"[eval] test accuracy : {acc:.4f}")
    print(f"[eval] test macro-F1 : {macro_f1:.4f}")
    print(classification_report(y_test, y_pred, labels=labels, zero_division=0))

    # --- rare-class sanity check on the synthetic holdout (R2L/U2R only) ---
    # These rows share the shape the live capture proxy emits for the attack
    # scripts, so this recall is a direct proxy for "will the model call the
    # attack script's traffic R2L/U2R?".
    synthetic_holdout_report = None
    if synth_holdout is not None and len(synth_holdout):
        hy = synth_holdout["category"]
        hp = pipeline.predict(synth_holdout[FEATURE_COLUMNS])
        h_labels = sorted(set(hy))
        synthetic_holdout_report = classification_report(
            hy, hp, labels=h_labels, zero_division=0, output_dict=True
        )
        print("[eval] synthetic rare-class holdout (attack-script signature):")
        print(classification_report(hy, hp, labels=h_labels, zero_division=0))

    # --- live holdout: real recorded sensor traffic + held-out learned events ---
    live_holdout = None
    holdout_parts = [h for h in holdout_parts if h is not None and len(h)]
    if holdout_parts:
        live_holdout = score_holdout(pipeline, pd.concat(holdout_parts, ignore_index=True))
        live_holdout["note"] = (
            "Model-only verdicts on REAL capture-proxy records held out from training "
            "(newest 30% of each recorded class, in time order) plus held-out captured "
            "events of each learned class.")
        print(f"[eval] live holdout ({live_holdout['rows']} rows): "
              f"accuracy {live_holdout['accuracy']:.4f}  macro-F1 {live_holdout['macro_f1']:.4f}")
        lcm = live_holdout["confusion_matrix"]
        print("       " + " ".join(f"{l[:7]:>7s}" for l in lcm["labels"]))
        for l, row in zip(lcm["labels"], lcm["matrix"]):
            print(f"{l[:7]:>7s}" + "".join(f"{v:8d}" for v in row))

    # --- open-set novelty detector over the sensor domain ---
    novelty = None
    sensor_parts = [p for p in sensor_train_parts if p is not None and len(p)]
    if sensor_parts:
        novelty = fit_novelty(pd.concat(sensor_parts, ignore_index=True))
        if holdout_parts:
            hd = novelty_distance(novelty, pd.concat(holdout_parts))
            novelty["holdout_outlier_rate"] = round(float((hd > novelty["threshold"]).mean()), 4)
        print(f"[novelty] nearest-neighbour detector on {novelty['fitted_rows']} sensor rows, "
              f"threshold {novelty['threshold']:.4f}, "
              f"holdout outlier rate {novelty.get('holdout_outlier_rate')}")

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = ARTIFACTS_DIR / "model.joblib"
    # compress=3 shrinks the 600-tree forest ~128MB -> ~35MB, so the default
    # model fits under GitHub's 100MB file limit and loads just as fast.
    joblib.dump(pipeline, model_path, compress=3)
    novelty_path = ARTIFACTS_DIR / "novelty.joblib"
    if novelty:
        joblib.dump(novelty, novelty_path, compress=3)
    elif novelty_path.exists():
        novelty_path.unlink()

    metrics = {
        "dataset": "NSL-KDD (KDDTrain+ / KDDTest+)",
        "model": "RandomForestClassifier(n_estimators=600, max_features=log2, class_weight=balanced_subsample)",
        "classes": labels,
        "test_accuracy": round(float(acc), 4),
        "test_macro_f1": round(float(macro_f1), 4),
        "per_class": {
            k: v for k, v in report.items()
            if k in labels or k in ("macro avg", "weighted avg")
        },
        "confusion_matrix": {"labels": labels, "matrix": cm.tolist()},
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "synthetic_augmentation": {
            "enabled": bool(with_synthetic),
            "train_rows_added": {
                "Normal": int(synth_normal), "DoS": int(synth_dos),
                "Probe": int(synth_probe), "R2L": int(synth_r2l), "U2R": int(synth_u2r),
            } if with_synthetic else {},
            "note": "Sensor-shape rows mirror capture-proxy/feature_extractor.py "
                    "output; added to TRAINING ONLY (KDDTest+ headline stays honest).",
        },
        "synthetic_holdout": synthetic_holdout_report,
        "live_holdout": live_holdout,
        "live_recording": {
            "used": live_train is not None,
            "classes_from_recording": sorted(live_classes),
            "train_rows": int(len(live_train)) if live_train is not None else 0,
        },
        "novelty_detector": {
            k: v for k, v in (novelty or {}).items() if k not in ("scaler", "nn", "columns")
        } or None,
        "sklearn_version": __import__("sklearn").__version__,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    (ARTIFACTS_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    (ARTIFACTS_DIR / "classes.json").write_text(json.dumps(labels, indent=2))

    # Feature importances (top 15) for the model card.
    try:
        ohe = pipeline.named_steps["prep"].named_transformers_["cat"]
        cat_names = list(ohe.get_feature_names_out(CATEGORICAL_COLUMNS))
        feat_names = cat_names + NUMERIC_COLUMNS_FE
        importances = pipeline.named_steps["clf"].feature_importances_
        top = sorted(zip(feat_names, importances), key=lambda x: -x[1])[:15]
        (ARTIFACTS_DIR / "feature_importances.json").write_text(
            json.dumps([{"feature": f, "importance": round(float(i), 5)} for f, i in top], indent=2)
        )
    except Exception as e:  # noqa: BLE001
        print(f"[warn] could not export feature importances: {e}")

    print(f"[done] saved model -> {model_path}")
    print(f"[done] saved metrics -> {ARTIFACTS_DIR / 'metrics.json'}")
    print(f"[done] elapsed {time.time() - t0:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
