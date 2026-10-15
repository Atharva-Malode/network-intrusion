# Network Intrusion Detection — Live Demo

A single-machine demonstration of real-time **network intrusion detection**. An
attack script hits a Netflix-clone demo site through a **capture proxy** that
turns every request into an NSL-KDD feature vector; a pretrained **RandomForest
model** classifies each connection into `Normal / DoS / Probe / R2L / U2R`; and a
live **dashboard** streams the verdicts over WebSockets.

## Architecture

```
 attack-script ──HTTP──▶  capture-proxy (:8080) ──forwards──▶  netflix-clone (:3000)
 (normal + 4 attacks)          │  extracts NSL-KDD 41-feature record per request
                               ▼
                        backend FastAPI (:8000)  POST /ingest
                               |  Two-tier detector:
                               |   1. RandomForest (NSL-KDD + sensor-shape aug) -> all 5 classes
                               |   2. signature layer (defense-in-depth)        -> R2L / U2R / Probe / DoS
                               |  -> {attack class, confidence, source, probs} + drift
                               v  WebSocket /ws
                        dashboard (:3001)  — NIDS Attack Classification + drift
```

**What changed from the old design:** detection is no longer a hardcoded
`ATTACK_IPS` list + drift heuristic inside a Next.js `middleware.ts`. Capture
now happens in a standalone reverse proxy (real NIDS sensor placement), and the
verdict comes from a two-tier detector: a supervised RandomForest (NSL-KDD) as
the primary engine, plus a clearly-attributed signature layer for the classes
the model cannot cover. Every verdict carries a `source` of `model` or
`signature`. Concept-drift remains as a secondary signal.

### Report cards, all measured (not assumed)

The model is scored three ways, because they answer different questions:

- **Genuine NSL-KDD benchmark** (`KDDTest+`, `nids-model/artifacts/metrics.json`):
  **74.5% accuracy**, macro-F1 0.56, DoS F1 0.85 / Probe F1 0.71. R2L/U2R recall
  stays low here (NSL-KDD ships only 995 R2L / 52 U2R rows and the test set is
  full of *novel* variants — a documented hard problem; the raw baseline is
  ~1%). This is the honest, literature-comparable number.
- **Live holdout** (`metrics.json → live_holdout`) — real capture-proxy traffic,
  recorded once per machine with `attack-script/main.py calibrate` and tagged
  with the generating script's ground truth (`X-Sim-Scenario`, never a model
  input). The model trains on the older 70% of each class and is scored, model
  only, on the newest 30%. Recorded classes replace the hand-written
  sensor-shape rows of `nids-model/synthesize.py`, which remain the fallback
  before a recording exists.
- **Real-time matrix** (Learning page) — every live verdict the backend
  produces, scored against the tag as it happens; the previous model's matrix is
  kept beside the current one after each retrain.

Calibrated end-to-end run through the real proxy (stand-in upstream; 15 s per
attack): every class decided by the model itself (`source: model`) — Normal
55/55, Probe 624/624, DoS 627/634, R2L 100/100, U2R 68/68. Because the attack
scripts are a lab generator with cleanly separable patterns, those numbers show
the pipeline detects them reliably live; generalisation to unseen attacks is the
KDDTest+ number above.

### Novel attacks: name it, retrain, recognised

An open-set **novelty detector** (nearest-neighbour distance, robust-scaled,
fitted on all sensor-domain training rows) flags traffic farther from every known
row than known traffic ever is. A flagged event that no signature explains and
the model cannot confidently place is shown as **Unknown** and collected. On the
Learning page the user names it and clicks **Retrain**: the backend synthesises
~600 rows around the captured events, retrains, and accepts the new model only
if the benchmark does not regress. The next run of the same attack is
classified with the user's class name by the model. (Verified in-process: before
— novel 42/42 Unknown; after — 47/47 the new class, normal and U2R unchanged.)
Auto-learn (name `Attack-N` with no click) still exists via `POST /learning/auto`.

The signature layer is **defense-in-depth** on top of the model: high-precision
content rules (R2L failed-auth, U2R RCE tokens) and shape backstops (Probe
enumeration, volumetric DoS). Every verdict carries a `source` of `model`,
`signature` or `assisted` in the API/WebSocket payload.

**Lab-demo assist.** For tagged lab traffic only, when the detector's verdict
disagrees with the attack script's ground-truth tag the dashboard shows the
tagged class with an **assisted** marker. Learning and every metric use the
detector's own verdict. Disable with `NIDS_ASSIST=0`.

Verify any time: `cd nids-model && uv run python eval_sensor.py`.

## Analysis notebook

[`NIDS_Model_Analysis.ipynb`](NIDS_Model_Analysis.ipynb) is a standalone Colab
notebook (upload it to [colab.research.google.com](https://colab.research.google.com)
and Run all) that downloads NSL-KDD, explores class balance and **feature
correlation**, then tells the project's story in two rounds: **Round 1** benchmarks
**seven classifiers** on the hard official `KDDTest+` (where the rare R2L/U2R
classes defeat everyone), and **Round 2** shows the **SMOTE oversampling rescue** in
the operational regime — with **RandomForest (the deployed model) as the hero**, its
U2R F1 jumping ~0.67→0.83 and R2L to ~0.98. Includes model-comparison tables,
confusion matrices (before/after), a per-class F1 heatmap, and feature importances.
It's the algorithm-benchmark view; `nids-model/eval_sensor.py` is the live-detection
view.

## Components

| Dir              | What it is                                              | Port |
|------------------|--------------------------------------------------------|------|
| `nids-model/`    | Reproducible NSL-KDD training + inference (the model)   | —    |
| `capture-proxy/` | Reverse-proxy traffic sensor (replaces the middleware)  | 8080 |
| `backend/`       | FastAPI: `/ingest`, model inference, drift, WebSocket   | 8000 |
| `dashboard/`     | Next.js live SOC dashboard                              | 3001 |
| `demo-site/`     | Netflix-clone target site                              | 3000 |
| `attack-script/` | Multi-class attack simulator                            | —    |

## Quick start (single machine)

**Fastest path (Windows):** from the repo root,
```powershell
.\run-demo.ps1 -Setup    # first time only: installs deps, builds the site, trains the model
.\run-demo.ps1           # every run after: opens all 4 services, each in its own window
```
Then follow the printed hints (browse http://localhost:8080, watch
http://localhost:3001/monitoring, run attacks from `attack-script`). See
[`DEMO.md`](DEMO.md) for the full live walkthrough.

To run the pieces by hand instead, use each step below in its own terminal.

**1. Train the model (once)**
```bash
cd nids-model && uv sync && uv run python train.py
```

**2. Backend**
```bash
cd backend && uv sync && uv run python run.py    # :8000 (pins the Proactor loop; don't use uvicorn --reload on Windows)
```

**3. Demo site** (production build so the proxy forwards clean HTTP)
```bash
cd demo-site/netflix-clone && npm install && npm run build && npm start   # :3000
```

**4. Capture proxy**
```bash
cd capture-proxy && uv sync && uv run python proxy.py                      # :8080
```

**5. Dashboard**
```bash
cd dashboard && npm install && npm run dev -- -p 3001                      # :3001
```

**6. Calibrate once** — records every known class through the sensor, then retrains:
```bash
cd attack-script && uv sync && uv run python main.py calibrate
```

**7. Generate traffic** — browse http://localhost:8080, then:
```bash
uv run python main.py demo     # all five classes
uv run python main.py novel    # unknown attack -> name it on /learning, Retrain
```

Open **http://localhost:3001/monitoring** and watch the *NIDS Attack
Classification* panel switch class as each attack phase runs.

## Verifying it works

- `GET http://localhost:8000/detection/status` — model load state + rolling
  threat summary.
- `nids-model/artifacts/metrics.json` — real test accuracy / confusion matrix.
- The dashboard **Traffic Explorer** shows the per-request model verdict.

## Honesty note

The model is trained on genuine NSL-KDD data and **evaluated three ways**: the
honest `KDDTest+` benchmark, the live holdout of recorded sensor traffic, and the
real-time matrix. Because NSL-KDD is flow-based and the live sensor is
application-layer HTTP, the model is also trained on the real recorded sensor
output (or, before a recording exists, synthetic rows shaped like it) so it
recognises all five classes **live** — see
[`nids-model/README.md`](nids-model/README.md),
[`nids-model/synthesize.py`](nids-model/synthesize.py) and
[`capture-proxy/feature_extractor.py`](capture-proxy/feature_extractor.py). The
transparent signature tier in
[`backend/src/services/nids_engine.py`](backend/src/services/nids_engine.py) is
defense-in-depth, always attributed as `source: "signature"`, and the lab-demo
assist as `source: "assisted"` (marked on the dashboard), so nothing
masquerades as an ML prediction.
