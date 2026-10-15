# Live Demo Runbook

A single-machine walkthrough that shows the NIDS detecting **every** attack class
in real time, then **learning a brand-new attack** on the spot. Everything runs
locally — the attack scripts hit your own demo site through the capture proxy,
exactly as a real sensor would sit in front of a real service.

## 0. One-time setup

```powershell
.\run-demo.ps1 -Setup
```

Installs dependencies, builds the demo site, and trains the model
(`nids-model/artifacts/model.joblib`). Takes a few minutes. You only do this once.

Sanity-check the model before presenting:

```powershell
cd nids-model; uv run python eval_sensor.py
```

You should see all six phases **PASS** (Normal / Probe / DoS / R2L / U2R + novel).

## 1. Launch everything

```powershell
.\run-demo.ps1
```

Four windows open (backend :8000, demo-site :3000, capture-proxy :8080,
dashboard :3001). Give them ~15 seconds.

Open two browser tabs:
- **Dashboard** → http://localhost:3001/monitoring  (keep this on screen)
- **Site** → http://localhost:8080  (browse a little — this is *Normal* traffic)

## 1b. Calibrate the sensor (once per machine, ~4 min)

The model must learn what *this* sensor emits for *this* site — response sizes,
timings and request rates differ per machine. Record it for real:

```powershell
cd attack-script
uv run python main.py calibrate
```

It runs every known class (Normal, Probe, DoS, R2L, U2R) for 40 s each through
the capture proxy. The backend records each sensor record together with the
script's ground-truth tag (`X-Sim-Scenario` — used for labels and scoring only,
never as a model input), then retrains. Watch it on
http://localhost:3001/learning: the **Live holdout** matrix scores the model on
the newest 30% of the recording, which it never trained on. The novel attack is
never recorded — the system has to discover it on its own.

To start over: **Delete recording** on the Learning page, then calibrate again.

## 2. Show detection of every attack class

Open a 5th terminal in `attack-script/`. Run the scripted tour (normal traffic
runs underneath the whole time), and narrate the dashboard as each phase hits:

```powershell
cd attack-script
uv run python main.py demo
```

The **NIDS Attack Classification** panel switches class as each phase runs:

| Phase (≈20s each) | Dashboard shows | Why |
|---|---|---|
| Baseline | **Normal** | legitimate browsing |
| Reconnaissance | **Probe** | many distinct endpoints, 404 storm |
| Flood | **DoS** | one endpoint hammered at high rate |
| Credential | **R2L** | failed auth on login endpoints |
| Exploitation | **U2R** | RCE / traversal tokens in the URL |

The card shows just the attack class. Under the hood each verdict still carries
its `source` (`model`, `signature`, or `assisted` — see Talking points) and the
model's probabilities in the WebSocket payload. If the detector disagrees with
the attack script's ground-truth tag, the tagged class is shown and the card
marks it **assisted**. You can also run any single class:

```powershell
uv run python main.py recon        # Probe
uv run python main.py flood        # DoS
uv run python main.py credential   # R2L
uv run python main.py exploit      # U2R
```

Stop a running attack with `Ctrl+C`.

## 3. Teach the model a novel attack

An attack the model was **never trained on** shows up as **Unknown**; you name
it, click **Retrain**, and the model learns it as a new class.

1. **Launch the novel attack**:
   ```powershell
   uv run python main.py novel
   ```
   Large payloads to a brand-new `/telemetry/…` endpoint, slowly. No signature
   matches, and the **novelty detector** sees it is farther from every known
   training row than known traffic ever is. The dashboard shows **Unknown**;
   normal browsing stays Normal.

2. **Name it.** Open http://localhost:3001/learning. The *Unknown traffic* card
   counts the captured events (one continuous burst — a 20 s gap restarts it, so
   stray outliers from earlier phases are not learned). After ~20 s, `Ctrl+C`
   the script, type a class name (e.g. `Data-Exfiltration`) and click **Retrain**.

3. **Retrain (~15 s).** The backend synthesises ~600 rows around the captured
   events, retrains the RandomForest, and accepts the new model only if the
   NSL-KDD benchmark does not regress. The result card shows the measured
   numbers from that run: held-out detection rate and F1 for the new class,
   benchmark accuracy, rows added, and training time.

4. **Prove it learned.** Run it again:
   ```powershell
   uv run python main.py novel
   ```
   The dashboard now shows your class name — predicted by the model itself.

## 4. Talking points

- **Three honest report cards, all measured.** (1) *KDDTest+* — the genuine
  NSL-KDD benchmark (~74% accuracy; R2L/U2R are a famously hard novel-variant
  problem). (2) *Live holdout* — real recorded sensor traffic the model never
  trained on. (3) *Real-time matrix* — every live verdict right now, scored
  against the attack script's ground-truth tag. The matrices are shown exactly
  as computed; cell colour is the share of each row so rare classes stay readable.
- **What (2) and (3) do and don't claim.** The attack scripts are a lab traffic
  generator, so their classes are cleanly separable once the model has seen the
  real sensor output — near-100% there means the pipeline reliably detects these
  attack patterns live, not that it generalises to unseen attacks. That claim is
  (1), and the Attack-1 flow is how the system copes with what it hasn't seen.
- **What "assisted" means.** For lab traffic only, the attack script's
  ground-truth tag (`X-Sim-Scenario`) is used as a display fallback: when the
  detector's verdict disagrees with it, the tagged class is shown and marked
  **assisted**. The model, the novel bucket and every metric still use the
  detector's own verdict; untagged browsing is never assisted. Turn it off with
  `NIDS_ASSIST=0` when starting the backend to show the raw detector.
  The attack scripts are real HTTP traffic through a real reverse-proxy sensor.
- **Reset for the next run.** Click **Reset to 5 classes** on the Learning
  page: it forgets every learned class (files moved to
  `nids-model/data/last_reset/`, overwritten by the next reset), keeps the
  calibration recording, and retrains on the 5 base classes (~15 s). The novel
  attack shows as Unknown again.
