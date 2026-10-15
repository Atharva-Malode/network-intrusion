"use client";

import { Detection, ThreatSummary } from "@/hooks/useSocket";
import { ShieldCheck, Crosshair, Radar, KeyRound, Terminal, ShieldAlert, Brain, Sparkles } from "lucide-react";

interface Props {
  detection: Detection | null;
  threatSummary: ThreatSummary;
}

type Meta = { color: string; bg: string; border: string; bar: string; icon: typeof ShieldCheck; label: string };

const CLASS_META: Record<string, Meta> = {
  Normal: { color: "text-emerald-400", bg: "bg-emerald-950/30", border: "border-emerald-500/40", bar: "bg-emerald-500", icon: ShieldCheck, label: "Normal Traffic" },
  DoS: { color: "text-rose-400", bg: "bg-rose-950/30", border: "border-rose-500/50", bar: "bg-rose-500", icon: Crosshair, label: "Denial of Service" },
  Probe: { color: "text-amber-400", bg: "bg-amber-950/30", border: "border-amber-500/50", bar: "bg-amber-500", icon: Radar, label: "Probe / Recon" },
  R2L: { color: "text-purple-400", bg: "bg-purple-950/30", border: "border-purple-500/50", bar: "bg-purple-500", icon: KeyRound, label: "Remote-to-Local" },
  U2R: { color: "text-fuchsia-400", bg: "bg-fuchsia-950/30", border: "border-fuchsia-500/50", bar: "bg-fuchsia-500", icon: Terminal, label: "User-to-Root / RCE" },
  Unknown: { color: "text-slate-400", bg: "bg-slate-900/40", border: "border-slate-700", bar: "bg-slate-600", icon: ShieldAlert, label: "Unknown" },
};

const ORDER = ["Normal", "DoS", "Probe", "R2L", "U2R"];

// Palette for classes learned live (Attack-1, …) that are not in CLASS_META.
const LEARNED_META: Omit<Meta, "label"> = { color: "text-teal-300", bg: "bg-teal-950/30", border: "border-teal-500/50", bar: "bg-teal-400", icon: Sparkles };
function metaFor(cls: string): Meta {
  return CLASS_META[cls] ?? { ...LEARNED_META, label: cls };
}

export default function ThreatClassificationCard({ detection, threatSummary }: Props) {
  const modelLoaded = detection?.model_loaded !== false;
  const isNovel = !!detection?.novel;
  const current = isNovel ? "Unknown" : (detection?.label || "Unknown");
  const meta = isNovel ? CLASS_META.Unknown : metaFor(current);
  const Icon = meta.icon;
  const assisted = detection?.source === "assisted";

  // Base classes always shown; learned classes appear once they are seen.
  const classes = [
    ...ORDER,
    ...Object.keys(threatSummary.class_counts).filter((c) => !ORDER.includes(c) && c !== "Unknown"),
  ];
  const totalClassified = classes.reduce((s, c) => s + (threatSummary.class_counts[c] || 0), 0) || 1;
  const dominant = threatSummary.dominant_attack;

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 backdrop-blur-xl shadow-xl space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Brain className="h-5 w-5 text-cyan-400" />
            <h2 className="text-lg font-bold text-white tracking-wide">
              NIDS Attack Classification
            </h2>
          </div>
          <p className="mt-0.5 text-xs text-slate-400">
            RandomForest (NSL-KDD + recorded live sensor traffic) · {classes.length}-class taxonomy
          </p>
        </div>
        <span
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[11px] font-bold border font-mono ${
            modelLoaded
              ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/30"
              : "bg-rose-500/10 text-rose-400 border-rose-500/30"
          }`}
        >
          {modelLoaded ? "MODEL ONLINE" : "MODEL NOT LOADED"}
        </span>
      </div>

      {!modelLoaded && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-950/20 p-4 text-sm text-rose-200">
          Model artifact not found. Train it first: <code className="text-rose-300">cd nids-model &amp;&amp; python train.py</code>
        </div>
      )}

      {/* Current verdict banner */}
      <div className={`flex items-center justify-between rounded-xl ${meta.bg} p-4 border ${meta.border}`}>
        <div className="flex items-center gap-3">
          <div className={`rounded-xl p-2.5 border ${meta.border} ${meta.color} ${current !== "Normal" && current !== "Unknown" ? "animate-pulse" : ""}`}>
            <Icon className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase tracking-widest text-slate-400 font-mono">Latest Classification</span>
              {isNovel && (
                <span className="rounded px-1.5 py-0.5 text-[9px] font-extrabold border bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/40">
                  NOVEL · UNKNOWN
                </span>
              )}
              {assisted && (
                <span
                  title="Lab demo: the detector disagreed with the attack script's tag, so the tagged class is shown."
                  className="rounded px-1.5 py-0.5 text-[9px] font-semibold border border-slate-700 text-slate-500"
                >
                  assisted
                </span>
              )}
            </div>
            <div className={`text-xl font-black ${meta.color} font-mono`}>{isNovel ? "Unknown" : meta.label}</div>
            <p className="text-xs text-slate-400 mt-0.5">
              {isNovel
                ? "Unlike any traffic the model was trained on — name it on the Learning page and retrain."
                : (detection?.description || "Awaiting traffic…")}
            </p>
          </div>
        </div>
      </div>

      {/* Rolling window distribution */}
      <div className="border-t border-slate-800/80 pt-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-400">
            Recent Window ({threatSummary.window_size} events)
          </div>
          {dominant && (
            <span className={`rounded px-2 py-0.5 text-[10px] font-extrabold ${metaFor(dominant).color} ${metaFor(dominant).bg} border ${metaFor(dominant).border}`}>
              DOMINANT THREAT: {dominant}
            </span>
          )}
        </div>
        <div className="grid gap-2 grid-cols-2" style={{ gridTemplateColumns: `repeat(auto-fit, minmax(90px, 1fr))` }}>
          {classes.map((c) => {
            const count = threatSummary.class_counts[c] || 0;
            const pct = (count / totalClassified) * 100;
            const m = metaFor(c);
            return (
              <div key={c} className={`rounded-lg border ${m.border} ${m.bg} p-3 text-center`}>
                <div className={`text-xl font-black font-mono ${m.color}`}>{count}</div>
                <div className="text-[10px] uppercase tracking-wide text-slate-400 font-mono">{c}</div>
                <div className="text-[10px] text-slate-500">{pct.toFixed(0)}%</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Top attacker IPs */}
      {threatSummary.top_attacker_ips.length > 0 && (
        <div className="border-t border-slate-800/80 pt-4">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Top Attacker Sources</div>
          <div className="flex flex-wrap gap-2">
            {threatSummary.top_attacker_ips.map((a) => (
              <span key={a.ip} className="inline-flex items-center gap-2 rounded-lg bg-rose-950/20 border border-rose-500/30 px-3 py-1.5 text-xs font-mono text-rose-300">
                <ShieldAlert className="h-3.5 w-3.5" />
                {a.ip}
                <span className="rounded bg-rose-500/20 px-1.5 py-0.5 text-[10px] font-bold">{a.count}</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
