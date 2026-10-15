"use client";

import { useCallback, useEffect, useState } from "react";
import Navbar from "@/components/NavBar";
import Footer from "@/components/Footer";
import { Brain, FlaskConical, Tag, RefreshCcw, AlertTriangle, CheckCircle2, RotateCcw } from "lucide-react";

const API = "http://127.0.0.1:8000";

interface Summary {
  label: string | null;
  reset: boolean;
  classes: string[];
  captured_events: number | null;
  synthetic_rows: number | null;
  train_rows: number | null;
  benchmark_accuracy: number | null;
  live_accuracy: number | null;
  new_class: { precision: number; recall: number; f1: number; heldout_rows: number } | null;
  seconds: number | null;
}
interface Status {
  pending: { bucket_name: string; pending_count: number; samples: Array<{ src_ip: string; path: string }> };
  retrain: {
    state: string; message: string; started: number | null; label: string | null;
    summary: Summary | null; human_intervention?: boolean; note?: string; reset?: boolean;
  };
  model: { classes: string[] };
}

const pct = (v: number | null | undefined) => (v == null ? "—" : `${(v * 100).toFixed(1)}%`);

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
      <div className="text-xs text-slate-400 uppercase">{label}</div>
      <div className="text-2xl font-black text-white font-mono mt-1">{value}</div>
      {sub && <div className="text-[11px] text-slate-500 font-mono mt-0.5">{sub}</div>}
    </div>
  );
}

export default function LearningPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [connected, setConnected] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(async () => {
    try {
      const r = await fetch(`${API}/learning/status`);
      if (r.ok) { setStatus(await r.json()); setConnected(true); }
    } catch { setConnected(false); }
    setNow(Date.now());
  }, []);

  useEffect(() => {
    // load() only setStates after an await, so this is not a synchronous cascade.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load();
    const t = setInterval(load, 1500);
    return () => clearInterval(t);
  }, [load]);

  const retrain = status?.retrain;
  const running = retrain?.state === "running";
  const pendingCount = status?.pending.pending_count ?? 0;
  const summary = retrain?.state === "done" ? retrain.summary : null;
  const failed = retrain?.state === "error" || retrain?.state === "review";
  const elapsed = running && retrain?.started ? Math.max(0, Math.round(now / 1000 - retrain.started)) : 0;
  const canRetrain = !!name.trim() && pendingCount > 0 && !running && !busy;

  const classes = status?.model.classes ?? [];

  const onReset = async () => {
    if (!window.confirm("Forget every learned class and retrain on the 5 base classes?")) return;
    setBusy(true);
    setError(null);
    try {
      const r = await fetch(`${API}/learning/reset`, { method: "POST" });
      const res = await r.json();
      if (res.status !== "started") setError(res.message ?? "Retraining is already running.");
      await load();
    } catch {
      setError("Backend not reachable.");
    } finally {
      setBusy(false);
    }
  };

  const onRetrain = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await fetch(`${API}/learning/retrain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name.trim() }),
      });
      const res = await r.json();
      if (res.status !== "started") setError(res.message ?? "Retraining is already running.");
      else setName("");
      await load();
    } catch {
      setError("Backend not reachable.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
      <Navbar connected={connected} totalRequests={0} />

      <main className="mx-auto max-w-5xl px-4 py-8 sm:px-6 space-y-8">
        <div className="border-b border-slate-800 pb-6 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white sm:text-3xl flex items-center gap-2">
              <Brain className="h-6 w-6 text-cyan-400" /> Learn a New Attack
            </h1>
            <p className="mt-1 text-sm text-slate-400">
              Traffic the model does not recognise is classified as Unknown and collected here. Give it a name and retrain — the model learns it as a new class.
            </p>
          </div>
          <div className="flex shrink-0 flex-col items-start gap-1 sm:items-end">
            <button
              onClick={onReset}
              disabled={!status || running || busy}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-xs font-bold text-slate-300 hover:border-slate-500 disabled:opacity-40"
            >
              <RotateCcw className="h-4 w-4" /> Reset to 5 classes
            </button>
            {classes.length > 0 && (
              <span className="text-[11px] text-slate-500 font-mono">model has {classes.length} classes</span>
            )}
          </div>
        </div>

        {/* Unknown traffic + name + retrain */}
        <div className="rounded-2xl border border-fuchsia-500/30 bg-fuchsia-950/10 p-6 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <FlaskConical className="h-5 w-5 text-fuchsia-400" /> Unknown traffic
            </h2>
            <span className="rounded-full bg-fuchsia-500/15 text-fuchsia-300 border border-fuchsia-500/40 px-3 py-1 text-xs font-mono font-bold">
              {pendingCount} events captured
            </span>
          </div>

          {pendingCount === 0 ? (
            <p className="text-sm text-slate-400">
              Nothing unknown yet. Run <code className="text-cyan-300">uv run python main.py novel</code> in attack-script/ and watch events arrive.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="border-b border-slate-800 text-slate-400 uppercase text-[11px] font-mono">
                  <tr><th className="py-2 px-3">Source IP</th><th className="py-2 px-3">Path</th></tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {status?.pending.samples.map((s, i) => (
                    <tr key={i}>
                      <td className="py-2 px-3">{s.src_ip}</td>
                      <td className="py-2 px-3 text-slate-400">{s.path}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="flex flex-wrap items-center gap-3 border-t border-slate-800/80 pt-4">
            <div className="flex items-center gap-2">
              <Tag className="h-4 w-4 text-cyan-400" />
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && canRetrain) onRetrain(); }}
                placeholder="Class name, e.g. Data-Exfiltration"
                className="rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none w-72 font-mono"
              />
            </div>
            <button
              onClick={onRetrain}
              disabled={!canRetrain}
              className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-2 text-sm font-bold text-slate-950 disabled:opacity-40 hover:brightness-110"
            >
              <RefreshCcw className={`h-4 w-4 ${running ? "animate-spin" : ""}`} />
              {running ? "Retraining…" : "Retrain"}
            </button>
          </div>
          {error && <p className="text-xs text-rose-300">{error}</p>}
        </div>

        {/* Retraining progress */}
        {running && (
          <div className="rounded-2xl border border-cyan-500/40 bg-cyan-950/20 p-6 space-y-3">
            <div className="flex items-center gap-2 text-sm font-bold text-cyan-300">
              <RefreshCcw className="h-4 w-4 animate-spin" />
              {retrain?.reset
                ? "Resetting to the 5 base classes"
                : `Retraining the model${retrain?.label ? ` with new class ${retrain.label}` : ""}`}… {elapsed}s
            </div>
            <div className="h-2 rounded bg-slate-800 overflow-hidden">
              <div className="h-full w-1/3 bg-gradient-to-r from-fuchsia-500 to-cyan-400 animate-pulse" />
            </div>
            <p className="text-xs text-slate-400">Generating training samples from the captured events, fitting the RandomForest, and evaluating on held-out data.</p>
          </div>
        )}

        {/* Retraining result */}
        {summary && (
          <div className="rounded-2xl border border-emerald-500/40 bg-emerald-950/10 p-6 space-y-5">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                {summary.reset ? "Reset to the 5 base classes" : summary.label ? `${summary.label} learned` : "Model retrained"}
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                {summary.reset
                  ? "All learned classes were removed. The novel attack shows as Unknown again."
                  : `The new model is live.${summary.label ? ` Run the novel attack again — it is now classified as ${summary.label}.` : ""}`}
              </p>
            </div>

            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {summary.new_class ? (
                <Stat
                  label={`${summary.label} detection`}
                  value={pct(summary.new_class.recall)}
                  sub={`F1 ${summary.new_class.f1.toFixed(3)} · ${summary.new_class.heldout_rows} held-out rows`}
                />
              ) : (
                <Stat label="Live accuracy" value={pct(summary.live_accuracy)} sub="held-out sensor traffic" />
              )}
              <Stat label="Benchmark accuracy" value={pct(summary.benchmark_accuracy)} sub="NSL-KDD KDDTest+" />
              <Stat
                label="New training data"
                value={summary.synthetic_rows != null ? summary.synthetic_rows.toLocaleString() : "—"}
                sub={summary.captured_events != null ? `rows from ${summary.captured_events} captured events` : undefined}
              />
              <Stat
                label="Training time"
                value={summary.seconds != null ? `${summary.seconds}s` : "—"}
                sub={summary.train_rows != null ? `${summary.train_rows.toLocaleString()} rows total` : undefined}
              />
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-slate-400">Classes:</span>
              {summary.classes.map((c) => (
                <span
                  key={c}
                  className={`rounded-lg border px-2.5 py-1 text-xs font-mono ${
                    c === summary.label
                      ? "bg-teal-950/40 border-teal-500/50 text-teal-300 font-bold"
                      : "bg-slate-950/60 border-slate-800 text-slate-300"
                  }`}
                >
                  {c}
                </span>
              ))}
            </div>
          </div>
        )}

        {failed && (
          <div className="rounded-2xl border border-amber-500/50 bg-amber-950/30 p-6 text-sm text-amber-200 flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 shrink-0 text-amber-400 mt-0.5" />
            <div>
              <div className="font-bold text-amber-300">{retrain?.message}</div>
              {retrain?.note && <p className="mt-1 text-xs leading-relaxed text-amber-100/90">{retrain.note}</p>}
            </div>
          </div>
        )}
      </main>

      <Footer />
    </div>
  );
}
