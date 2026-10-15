# Backend — NIDS & Concept-Drift Sentinel API

FastAPI service: ingests connection feature records from the capture proxy,
classifies them with the NSL-KDD model + signature layer, tracks concept drift,
runs active learning, and powers the dashboard over REST + WebSocket.

```bash
cd backend
uv sync                 # or: pip install -e .
uv run python run.py    # launcher: pins the Windows Proactor loop (see below)
```

> **Do not use `uvicorn --reload` on Windows for this service.** Under a flood the
> server opens many sockets; `--reload` forces asyncio's `SelectorEventLoop`,
> whose `select()` caps at 512 descriptors, so the loop crashes with
> `ValueError: too many file descriptors in select()`. `run.py` pins the Proactor
> loop (IOCP, no limit) and runs a single in-process worker.

## Model wiring

`src/services/nids_engine.py` loads `../nids-model/artifacts/model.joblib` — a
self-contained scikit-learn Pipeline (feature engineering → one-hot → tuned
RandomForest, 5-class). The pipeline pickles a reference to
`nids-model/features.py::engineer_features`, so `load_model()` puts the
`nids-model` directory on `sys.path` before `joblib.load` to resolve it. Nothing
else is needed — retrain in `nids-model/` and the backend hot-reloads on the next
`/learning/retrain`.

## Active learning + novelty

- Uncertain, non-signature events seen while drift is elevated are flagged
  `novel` in `/ingest` and collected into an "Attack-N" bucket
  (`src/services/learning_engine.py`).
- `POST /learning/label` names a bucket and synthesises samples;
  `POST /learning/retrain` retrains in the background.

### Retrain safety guardrail

`/learning/retrain` snapshots the current model first, then compares the new
model's `macro-F1`/`accuracy` against the previous. If the new model regresses on
**both** beyond `_QUALITY_MARGIN` (0.02), it is **rejected**: the previous model
is restored and kept serving, and the retrain status returns
`state: "review"`, `human_intervention: true`, and a `note` explaining what
happened. The Learning page surfaces this as a "Human intervention needed"
banner. If training crashes, the previous model is likewise kept.

## "Explain this" (Gemini)

`POST /explain` (or `GET /explain`) returns a one-paragraph, plain-language
summary of the current situation (latest verdict + threat summary + drift). The
dashboard's **Explain this** button calls it with the on-screen snapshot.

Configure the key in `backend/.env` (git-ignored; copy from `.env.example`):

```
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-1.5-flash
```

With no key it returns a deterministic **local summary** so the feature works out
of the box; the moment a valid key is added it upgrades to Gemini automatically
(re-read per request, no restart needed). The key is never logged or returned to
the client.
