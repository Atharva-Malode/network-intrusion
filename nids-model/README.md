# NIDS Model — NSL-KDD Network Intrusion Detection

A reproducible, supervised network-intrusion detection model that classifies
each connection into one of five canonical classes:

| Class    | Meaning                                                        |
|----------|---------------------------------------------------------------|
| `Normal` | Legitimate traffic                                            |
| `DoS`    | Denial of Service — flooding / resource exhaustion           |
| `Probe`  | Reconnaissance — scanning, enumeration, fingerprinting       |
| `R2L`    | Remote-to-Local — unauthorized remote access (auth abuse)    |
| `U2R`    | User-to-Root — privilege escalation / remote code execution  |

## Model lineage (why this is "valid")

- **Dataset:** [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) — the
  de-duplicated successor to KDD Cup 99 from the Canadian Institute for
  Cybersecurity (UNB). It is the canonical academic benchmark for NIDS.
- **Schema:** the standard 41 connection features + the DoS/Probe/R2L/U2R
  taxonomy used across the literature and reference repos such as
  [100divyadg/netdefender](https://github.com/100divyadg/netdefender) and
  [thinline72/nsl-kdd](https://github.com/thinline72/nsl-kdd).
- **Model:** `RandomForestClassifier` (600 trees, `max_features=log2`,
  `class_weight=balanced_subsample`) inside a scikit-learn `Pipeline` that
  one-hot-encodes the categorical columns and adds engineered features
  (`log1p` of heavy tails + a `content_score`; see `features.py`).
- **Evaluation:** trained on `KDDTrain+`, scored on the official `KDDTest+`
  split. Real accuracy / macro-F1 / confusion matrix are written to
  `artifacts/metrics.json`. (NSL-KDD's held-out test set contains novel attack
  types, so a realistic RF lands around ~0.75–0.78 accuracy — this is expected
  and honest, not a bug.)

## Why train instead of downloading a `.pkl`

Pretrained scikit-learn pickles are version-locked and carry a specific
preprocessing chain; loading a stranger's `.pkl` across sklearn versions is the
#1 replicability failure. Here you build the **same canonical model** locally
against your own pinned environment, so it is guaranteed reproducible.

## Run

```bash
cd nids-model
uv sync            # or: pip install -e .
uv run python train.py
```

Flags:
- `--no-synthetic` — train on raw NSL-KDD only (reproduces the imbalanced baseline).
- `--synth-r2l N` / `--synth-u2r N` — R2L/U2R synthetic volume (defaults 8000 / 6000).
- `--synth-probe N` / `--synth-dos N` / `--synth-normal N` — sensor-shape volume
  for the traffic-shape classes (defaults 1500 / 1500 / 0).
- `--sensor-fraction F` — fraction of R2L/U2R rows in the live-proxy "sensor"
  flavour vs the genuine "classic" flavour (default 0.25).
- `--with-custom` — also fold in `data/custom_labeled.csv` (active-learning).

Outputs in `artifacts/`:
- `model.joblib` — the fitted Pipeline (this is what the backend loads)
- `metrics.json` — accuracy, macro-F1, per-class report, confusion matrix,
  plus a `synthetic_holdout` report scoring the rare classes on the live
  attack-script signature
- `classes.json`, `feature_importances.json`

## Fixing the starved rare classes (R2L / U2R) — synthetic oversampling

NSL-KDD ships only **995 R2L and 52 U2R** training rows against 67k Normal / 46k
DoS. Baseline recall on those two classes is ~0.008 / 0.015 — the model learns
almost nothing about them, and the live attack scripts
([`credential.py`](../attack-script/credential.py) → R2L,
[`exploit.py`](../attack-script/exploit.py) → U2R) never get an R2L/U2R call out
of the model itself.

[`synthesize.py`](synthesize.py) oversamples both classes with realistic,
feature-consistent synthetic connection records, added to **training only** so
the `KDDTest+` headline stays an honest, literature-comparable benchmark. Each
class is generated in two flavours:

- **classic** — mirrors the genuine NSL-KDD R2L/U2R distribution (ftp/telnet
  sessions, `logged_in`, `hot` / `num_root` / `root_shell` indicators). Lifts
  real-`KDDTest+` recall (U2R ~0.015 → ~0.12, R2L likewise improved) without
  regressing Normal/DoS/Probe.
- **sensor** — mirrors exactly what the [capture-proxy](../capture-proxy) emits
  for the attack scripts (`service=http`, `REJ` flag, the HTTP-derived
  `num_failed_logins` / `root_shell` / `num_root` / `hot` content features), with
  the traffic-shape features (`count`, `same_srv_rate`, `serror`/`rerror`) drawn
  independently across their full range so the **content** indicator owns the
  verdict regardless of attack pacing. This is what makes the live attack scripts
  land on the rare class in the **model**, not just the signature tier.

The `synthetic_holdout` block in `metrics.json` scores a separately-seeded
sample of these signatures (R2L/U2R recall ≈ 1.0), and end-to-end the live
sensor + model now classify `credential.py` as R2L and `exploit.py` as U2R while
normal browsing stays Normal.

Quick inference check:
```bash
uv run python predict.py
```

## Reproducing the SVM-SMOTE paper (Tauscher et al., 2021)

[`reproduce_paper.py`](reproduce_paper.py) reproduces Table III of
[arXiv:2108.08394](https://arxiv.org/abs/2108.08394), whose headline is
**F1_U2R ≈ 0.57** on NSL-KDD with SVM-SMOTE oversampling.

```bash
uv run python reproduce_paper.py            # pooled protocol (default)
uv run python reproduce_paper.py --protocol all
```

Two things about that paper that aren't obvious from the number:

1. **It's a 4-class, attacks-only task.** The paper uses a two-stage hierarchy —
   binary (Normal vs attack) first, then a 4-class classifier over
   {DoS, Probe, R2L, U2R} on the attack samples *only*. Table III lives in that
   attack-only subspace, not the 5-class problem our production model solves.
2. **How the oversampling is done:** `imblearn`'s `SVMSMOTE` is fit on the
   **training split only** and balances every attack class up to the majority by
   interpolating new synthetic points near the SVM decision border. It is *not*
   applied to the test set.

The catch — and the reason a naive attempt "doesn't reproduce" — is the
**evaluation split**. SVM-SMOTE can only lift U2R F1 to ~0.57 when the test U2R
samples are drawn from the *same distribution* as training (a stratified split).
On the official `KDDTest+`, R2L/U2R are largely **novel** variants, so
oversampling can't help (it actually hurts U2R). Verified here:

| protocol | setting | U2R F1 | macro-F1 |
|----------|---------|:------:|:--------:|
| pooled (`KDDTrain+`∪`KDDTest+`, stratified split) | SVM-SMOTE | **0.59** | 0.89 |
| split (`KDDTrain+` only, stratified split)        | SVM-SMOTE | **0.59** | 0.89 |
| test (official `KDDTest+`)                         | baseline  | 0.50 | 0.68 |
| test (official `KDDTest+`)                         | SVM-SMOTE | 0.27 | 0.63 |

So the paper's 0.57 is real and reproducible (we get ~0.59) — but it is a
**same-distribution** result. In the pooled protocol, oversampling's real effect
is on the precision/recall trade: it lifts U2R **recall** from 0.46 → 0.75 (F1
stays ~0.59), i.e. it catches more of the rare attacks at the cost of precision.
This is a separate, academic reproduction; it does not change the production
`model.joblib`, which is the honest one-hot RandomForest evaluated on the real
`KDDTest+`.

## Pushing the rare classes higher on the honest benchmark

[`improve_rare.py`](improve_rare.py) asks the follow-up question: on the *hard*
number — the official `KDDTest+`, where R2L/U2R are novel variants — can we beat
the paper-style MLP + SVM-SMOTE for the rare classes? It sweeps
classifier × resampling strategy (SMOTE / SVM-SMOTE / Borderline / ADASYN /
SMOTE+ENN / SMOTE+Tomek / moderate) and ranks by macro- and rare-class F1.

```bash
uv run python improve_rare.py          # full sweep + winner
uv run python improve_rare.py --best   # just the winning config
```

**Finding:** on novel-variant test data, **oversampling does not help the rare
classes** — every SMOTE variant matched or *hurt* the no-resampling result. The
lever is the **model**. A plain `RandomForest(600 trees, max_features='log2')`
with no resampling wins:

| setting (4-class, attacks-only, official KDDTest+) | R2L F1 | U2R F1 | macro-F1 |
|-----------------------------------------------------|:------:|:------:|:--------:|
| paper-style MLP + SVM-SMOTE (baseline)              |  0.58  | 0.46–0.50 | 0.68 |
| **RandomForest(600, log2), no resampling (winner)** | **0.71** | **0.52** | **0.71** |

So R2L F1 climbs 0.58 → **0.71** and macro-F1 0.68 → **0.71**, with U2R at 0.52.
The intuition matches the domain: R2L/U2R are defined by *content* features
(`num_failed_logins`, `hot`, `root_shell`, …), which trees split on directly —
synthesising more minority points in a shifted feature space just adds noise.

### Round 2 — extending the reach ([`improve_rare_v2.py`](improve_rare_v2.py))

Building on that, round 2 adds **feature engineering** (`log1p` of the
heavy-tailed byte/count features + content ratios), a **class-weighted XGBoost**,
a soft-voting ensemble, and optional validation-tuned per-class priors.

```bash
uv run python improve_rare_v2.py
```

Winner: **XGBoost (balanced sample weights) + engineered features**.

| setting (4-class, attacks-only, official KDDTest+) | R2L F1 | U2R F1 | U2R recall | macro-F1 |
|-----------------------------------------------------|:------:|:------:|:----------:|:--------:|
| paper-style MLP + SVM-SMOTE                          |  0.58  |  0.50  |    0.33    |   0.68   |
| round-1 RandomForest(600, log2)                      |  0.71  |  0.52  |    0.49    |   0.71   |
| **round-2 XGBoost(balanced) + features**             | **0.72** | **0.57** | **0.72** | **0.72** |

The headline "reach" gain is **U2R recall 0.33 → 0.72** — the model now catches
48 of 67 novel U2R attacks (vs 33), with R2L F1 up to 0.72. Balanced sample
weights make the booster pay attention to the rare classes without synthesising
fake data, and the log/ratio features sharpen the R2L↔Probe boundary that was
the dominant error. (A logistic stacker and heavy prior-boosting were tried and
dropped — the stacker collapsed U2R and the priors didn't generalise past the
validation split.)

## Honest note on the live feature mapping

NSL-KDD was built from packet/flow captures. When this model runs **live**, the
[capture-proxy](../capture-proxy) is an application-layer HTTP sensor, so it can
observe some NSL-KDD features exactly (byte counts, duration, and the
time/host-window statistics that encode DoS and Probe) but must **derive** the
content-based ones (`root_shell`, `num_failed_logins`, `hot`, …) from HTTP
attack indicators (sensitive-path access, failed auth, RCE tokens in the URL).

Left untreated, the live HTTP sensor's feature distribution only overlaps the
model's training distribution for a couple of classes: recon (`Probe`) reads as
`Normal`, and floods (`DoS`) survive only on the volumetric signature. So
[`synthesize.py`](synthesize.py) generates a **sensor** flavour for **all**
attack classes — Probe (404-storm shape), DoS (single-endpoint high-rate shape)
and the R2L/U2R content shapes — mirroring exactly what
[`feature_extractor.py`](../capture-proxy/feature_extractor.py) emits, added to
**training only** so the `KDDTest+` benchmark stays honest. The model then owns
all five classes on the live sensor directly.

### Live-sensor report card — `eval_sensor.py`

`metrics.json` scores genuine NSL-KDD packets; **`eval_sensor.py` scores the live
sensor** — the distribution the demo runs on. It replays each attack script's
real request pattern (imported straight from `attack-script/`, so it can't drift)
through the real capture-proxy `FeatureExtractor` and the backend's two-tier
`classify()`, with normal traffic interleaved and a controllable clock, then
reports per-class detection rate and exits non-zero if any class regresses.

```bash
uv run python eval_sensor.py            # human report
uv run python eval_sensor.py --json     # machine-readable, for CI/regression
```

Current result: **Normal 100 · Probe 99.6 · DoS 97.4 · R2L 100 · U2R 100**, and
novel traffic (`novel.py`) stays model-`Normal`/uncertain so it is flagged novel
for active learning rather than mislabelled. A transparent **signature tier** in
[`backend/src/services/nids_engine.py`](../backend/src/services/nids_engine.py)
adds defence-in-depth on top (content rules for R2L/U2R that override a
shape-class guess, plus Probe/DoS backstops), always attributed as
`source: "signature"` so nothing masquerades as an ML prediction.
