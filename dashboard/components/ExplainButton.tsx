"use client";

import { useCallback, useEffect, useState } from "react";
import { Sparkles, X, Loader2, Bot, Info } from "lucide-react";
import { Detection, ThreatSummary, DriftData } from "@/hooks/useSocket";

const API = "http://127.0.0.1:8000";

interface Props {
  detection: Detection | null;
  threatSummary: ThreatSummary;
  drift: DriftData;
}

interface ExplainResponse {
  explanation: string;
  source: "gemini" | "groq" | "fallback";
  note?: string;
}

export default function ExplainButton({ detection, threatSummary, drift }: Props) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ExplainResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const explain = useCallback(async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const r = await fetch(`${API}/explain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          detection,
          threat_summary: threatSummary,
          drift,
        }),
      });
      if (!r.ok) throw new Error(`Backend returned ${r.status}`);
      setResult(await r.json());
    } catch (e: unknown) {
      setError(
        "Couldn't reach the backend. Is it running on :8000? " +
          (e instanceof Error ? e.message : "")
      );
    } finally {
      setLoading(false);
    }
  }, [detection, threatSummary, drift]);

  const onClick = () => {
    setOpen(true);
    explain();
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    if (open) window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <>
      <button
        onClick={onClick}
        className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-violet-500 to-fuchsia-600 px-4 py-2 text-sm font-bold text-white shadow-lg shadow-fuchsia-900/30 hover:brightness-110 transition"
        title="Explain the current situation in plain language"
      >
        <Sparkles className="h-4 w-4" /> Explain this
      </button>

      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div
            className="fixed inset-0 bg-slate-950/80 backdrop-blur-md"
            onClick={() => setOpen(false)}
          />
          <div className="relative w-full max-w-xl rounded-2xl border border-fuchsia-500/30 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-start justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <div className="rounded-xl border border-fuchsia-500/40 bg-fuchsia-500/15 p-2">
                  <Bot className="h-5 w-5 text-fuchsia-300" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">AI Explanation</h3>
                  <p className="text-[11px] text-slate-400">
                    Plain-language read of the current situation
                  </p>
                </div>
              </div>
              <button
                onClick={() => setOpen(false)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="pt-4 min-h-[96px] max-h-[60vh] overflow-y-auto">
              {loading && (
                <div className="flex items-center gap-2 text-sm text-slate-400">
                  <Loader2 className="h-4 w-4 animate-spin text-fuchsia-400" />
                  Analyzing live data…
                </div>
              )}
              {error && (
                <p className="text-sm text-rose-300">{error}</p>
              )}
              {result && (
                <>
                  <div className="space-y-3 text-sm leading-relaxed text-slate-100">
                    {result.explanation
                      .split(/\n{2,}/)
                      .map((para) => para.trim())
                      .filter(Boolean)
                      .map((para, i) => (
                        <p key={i}>{para}</p>
                      ))}
                  </div>
                  <div className="mt-4 flex items-center gap-2">
                    <span
                      className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-[10px] font-bold font-mono border ${
                        result.source === "gemini" || result.source === "groq"
                          ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/40"
                          : "bg-slate-700/40 text-slate-300 border-slate-600"
                      }`}
                    >
                      <Sparkles className="h-3 w-3" />
                      {result.source === "gemini"
                        ? "Gemini"
                        : result.source === "groq"
                        ? "Groq"
                        : "Local summary"}
                    </span>
                    <button
                      onClick={explain}
                      className="text-[11px] text-fuchsia-300 hover:text-fuchsia-200 font-semibold"
                    >
                      Regenerate
                    </button>
                  </div>
                  {result.note && (
                    <p className="mt-3 flex items-start gap-1.5 text-[11px] text-slate-500">
                      <Info className="h-3.5 w-3.5 mt-0.5 shrink-0" /> {result.note}
                    </p>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
