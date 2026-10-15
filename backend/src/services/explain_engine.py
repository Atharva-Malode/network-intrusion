"""
Natural-language "Explain this" engine.

Takes the current live situation (latest verdict + rolling threat summary +
drift + learning state) and returns ONE short plain-language paragraph a
non-expert can read.

Uses Google Gemini when a key is configured (backend/.env -> GEMINI_API_KEY);
until then it falls back to a deterministic local summary built from the same
data, so the button works out of the box and upgrades automatically the moment
a real key is dropped in. No key is ever logged or returned to the client.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
from dotenv import load_dotenv

# Load backend/.env once at import (searches this file's project root).
_BACKEND_DIR = Path(__file__).resolve().parents[2]
load_dotenv(_BACKEND_DIR / ".env")

# gemini-1.5-* was retired by Google (404 on generateContent); 2.5-flash is the
# current stable default. Read per-call so a .env change is picked up without a
# restart (mirrors _api_key). 2.5-flash is a "thinking" model — see _call_gemini.
DEFAULT_MODEL = "gemini-3.5-flash"
_GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def _model() -> str:
    return (os.getenv("GEMINI_MODEL") or DEFAULT_MODEL).strip() or DEFAULT_MODEL


def _api_key() -> str:
    # Re-read each call so a freshly added key is picked up without a restart.
    load_dotenv(_BACKEND_DIR / ".env", override=True)
    return (os.getenv("GEMINI_API_KEY") or "").strip()


# Groq (OpenAI-compatible chat completions) is the fallback LLM provider: if
# Gemini has no key or errors, we try Groq before degrading to the local summary.
# Groq retires/renames models over time; list live ones at
# GET https://api.groq.com/openai/v1/models. openai/gpt-oss-20b is a fast,
# capable current chat model. Override with GROQ_MODEL in .env.
DEFAULT_GROQ_MODEL = "openai/gpt-oss-20b"
_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def _groq_model() -> str:
    return (os.getenv("GROQ_MODEL") or DEFAULT_GROQ_MODEL).strip() or DEFAULT_GROQ_MODEL


def _groq_key() -> str:
    load_dotenv(_BACKEND_DIR / ".env", override=True)
    return (os.getenv("GROQ_API_KEY") or "").strip()


def _context(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Merge the client's on-screen snapshot with authoritative server state."""
    from src.services import nids_engine
    from src.services.drift_engine import get_cached_drift

    detection = payload.get("detection") or {}
    threat = payload.get("threat_summary") or nids_engine.threat_summary()
    drift = payload.get("drift") or get_cached_drift()
    techniques = (drift.get("techniques") or {})
    drift_firing = [t.get("name", k) for k, t in techniques.items() if t.get("drift")]
    return {
        "verdict": detection.get("label", "—"),
        "confidence": detection.get("confidence"),
        "model_said": detection.get("model_label"),
        "novel": detection.get("novel"),
        "novelty_score": detection.get("novelty_score"),
        "uncertain": detection.get("uncertain"),
        "signature": (detection.get("signature") or {}).get("reason"),
        "dominant_attack": threat.get("dominant_attack"),
        "attack_ratio": threat.get("attack_ratio"),
        "window_size": threat.get("window_size"),
        "class_counts": threat.get("class_counts"),
        "top_ips": [i.get("ip") for i in (threat.get("top_attacker_ips") or [])][:3],
        "drift_status": drift.get("status"),
        "drift_score": drift.get("overall_drift_score"),
        "drift_firing": drift_firing,
    }


def _prompt(ctx: Dict[str, Any]) -> str:
    return (
        "You are a SOC (security operations) analyst assistant for a live network "
        "intrusion detection dashboard. Explain the CURRENT situation to a "
        "non-expert in TWO short paragraphs (about 5-7 sentences total), in plain "
        "language, with no jargon and no bullet points.\n"
        "Paragraph 1 — what the system is seeing right now and how serious it "
        "looks: the latest verdict and how confident the detector is, roughly how "
        "much of the recent traffic looks malicious and which attack type "
        "dominates, and whether the traffic has drifted from its normal baseline.\n"
        "Paragraph 2 — the evidence and the response: point to the concrete signals "
        "(the attacking source IPs, any signature reason, which drift measures "
        "fired, or that the pattern is novel/unknown and unlike anything the model "
        "was trained on), then give one clear, reasonable next step a defender "
        "should take.\n\n"
        f"Live data (JSON): {ctx}\n\n"
        "Field notes: 'model_said' is the model's own raw class; 'novelty_score' "
        "above 1 means the traffic is unlike anything the model was trained on; "
        "'drift_firing' lists which statistical drift tests triggered; "
        "'window_size' is how many recent events the summary covers.\n"
        "Class meanings: Normal=benign; DoS=flooding; Probe=scanning; "
        "R2L=remote credential/auth abuse; U2R=privilege escalation/RCE; "
        "novel=an unknown pattern the model was not trained on. If the verdict is "
        "Normal and nothing is drifting, say plainly and briefly that things look "
        "calm rather than inventing a threat."
    )


def _fallback(ctx: Dict[str, Any]) -> str:
    """Deterministic local explanation used when no Gemini key is configured."""
    verdict = ctx.get("verdict") or "—"
    drift = ctx.get("drift_status") or "NORMAL"
    ratio = ctx.get("attack_ratio")
    dom = ctx.get("dominant_attack")
    ips = ctx.get("top_ips") or []

    human = {
        "Normal": "legitimate traffic with no intrusion signature",
        "DoS": "a denial-of-service flood",
        "Probe": "reconnaissance scanning",
        "R2L": "remote credential/authentication abuse",
        "U2R": "an attempt to gain elevated (root) access or run code",
    }
    conf = ctx.get("confidence")
    conf_txt = (f" with {round(conf * 100)}% confidence"
                if isinstance(conf, (int, float)) else "")
    if ctx.get("novel"):
        lead = ("The system is seeing an unusual pattern it was not trained on, "
                "so it has flagged the traffic as novel for review")
    else:
        lead = (f"The latest request was classified as {verdict}{conf_txt} — "
                + human.get(verdict, "an unrecognized pattern"))

    pct = f"{round((ratio or 0) * 100)}%" if ratio is not None else "an unknown share"
    mid = (f" Over the recent window about {pct} of traffic looks malicious"
           + (f", mostly {dom}." if dom else "."))
    drift_note = {
        "NORMAL": " The traffic distribution is stable (no concept drift), so the model's view is reliable.",
        "WARNING": " Traffic is starting to drift from the baseline, so keep an eye on new patterns.",
        "CRITICAL": " Traffic has drifted sharply from the baseline, which often accompanies an active attack.",
    }.get(drift, "")

    # Evidence paragraph: which drift tests fired, how far outside known traffic.
    firing = ctx.get("drift_firing") or []
    nov = ctx.get("novelty_score")
    evidence = ""
    if firing:
        evidence += f" The drift measures that triggered were {', '.join(firing)}."
    if isinstance(nov, (int, float)) and nov > 1:
        evidence += (f" The traffic sits well outside everything the model was "
                     f"trained on (novelty score {nov}, where above 1 is unknown).")
    ip_note = f" The main source(s) to watch are {', '.join(ips)}." if ips else ""
    action = (" Recommended next step: review the flagged sources and, if this is a "
              "new attack type, label it on the Learning page and retrain."
              if verdict != "Normal" or ctx.get("novel") or drift != "NORMAL"
              else " No action is needed right now; continue monitoring.")
    return (lead + "." + mid + drift_note + evidence + ip_note + action).replace("..", ".")


def _call_gemini(prompt: str, key: str) -> tuple[Optional[str], Optional[str]]:
    """Return (text, None) on success or (None, reason) on failure.

    The reason is a short, key-free string safe to surface on the dashboard, so
    a misconfiguration (retired model, bad key, quota) is diagnosable instead of
    silently degrading to the local summary.
    """
    model = _model()
    url = _GEMINI_URL.format(model=model)
    try:
        r = httpx.post(
            url,
            params={"key": key},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "maxOutputTokens": 800,
                    "temperature": 0.4,
                    # 2.5-flash "thinks" by default; with a small token budget the
                    # thinking can consume it all and the reply comes back with no
                    # text parts. Disable it so the budget produces the answer.
                    "thinkingConfig": {"thinkingBudget": 0},
                },
            },
            timeout=20.0,
        )
        if r.status_code != 200:
            try:
                msg = r.json().get("error", {}).get("message", "") or r.text
            except Exception:  # noqa: BLE001
                msg = r.text
            return None, f"HTTP {r.status_code} for model '{model}': {msg[:200]}"
        data = r.json()
        cand = (data.get("candidates") or [{}])[0]
        parts = (cand.get("content") or {}).get("parts") or []
        text = " ".join(p.get("text", "") for p in parts if isinstance(p, dict)).strip()
        if text:
            return text, None
        return None, f"empty response from '{model}' (finishReason={cand.get('finishReason')})"
    except Exception as e:  # noqa: BLE001
        return None, f"request error contacting '{model}': {e!r}"


def _call_groq(prompt: str, key: str) -> tuple[Optional[str], Optional[str]]:
    """Groq (OpenAI-compatible chat completions) — the fallback LLM provider.
    Same (text, reason) contract as _call_gemini so explain() can chain them."""
    model = _groq_model()
    try:
        r = httpx.post(
            _GROQ_URL,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 800,
                "temperature": 0.4,
            },
            timeout=20.0,
        )
        if r.status_code != 200:
            try:
                msg = r.json().get("error", {}).get("message", "") or r.text
            except Exception:  # noqa: BLE001
                msg = r.text
            return None, f"HTTP {r.status_code} for model '{model}': {msg[:200]}"
        data = r.json()
        text = ((data.get("choices") or [{}])[0].get("message") or {}).get("content", "").strip()
        if text:
            return text, None
        return None, f"empty response from Groq model '{model}'"
    except Exception as e:  # noqa: BLE001
        return None, f"request error contacting Groq model '{model}': {e!r}"


def explain(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate the plain-language explanation, trying LLM providers in order
    (Gemini -> Groq) and degrading to a deterministic local summary. Each
    provider's failure reason is surfaced so a misconfiguration is diagnosable."""
    ctx = _context(payload or {})
    prompt = _prompt(ctx)
    errors = []

    gkey = _api_key()
    if gkey:
        text, err = _call_gemini(prompt, gkey)
        if text:
            return {"explanation": text, "source": "gemini", "context": ctx}
        errors.append(f"Gemini failed ({err})")

    grkey = _groq_key()
    if grkey:
        text, err = _call_groq(prompt, grkey)
        if text:
            return {"explanation": text, "source": "groq", "context": ctx}
        errors.append(f"Groq failed ({err})")

    if errors:
        note = "; ".join(errors) + " — showing a local summary."
    else:
        note = ("No GEMINI_API_KEY or GROQ_API_KEY set in backend/.env — showing a "
                "local summary. Add either key to enable AI explanations.")
    return {"explanation": _fallback(ctx), "source": "fallback", "note": note, "context": ctx}
