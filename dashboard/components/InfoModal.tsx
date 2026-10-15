"use client";

import { useEffect } from "react";
import { X, Info, HelpCircle, CheckCircle2, AlertTriangle, Lightbulb } from "lucide-react";

export interface ModalInfoContent {
  title: string;
  category?: string;
  badge?: string;
  badgeColor?: "cyan" | "emerald" | "amber" | "rose" | "purple";
  summary: string;
  keyPoints?: string[];
  normalVsAnomaly?: {
    normal: string;
    anomaly: string;
  };
  howToTest?: string;
  formula?: string;
}

interface InfoModalProps {
  isOpen: boolean;
  onClose: () => void;
  content: ModalInfoContent | null;
}

export default function InfoModal({ isOpen, onClose, content }: InfoModalProps) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (isOpen) {
      document.body.style.overflow = "hidden";
      window.addEventListener("keydown", handleKeyDown);
    } else {
      document.body.style.overflow = "unset";
    }
    return () => {
      document.body.style.overflow = "unset";
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen, onClose]);

  if (!isOpen || !content) return null;

  const colorMap = {
    cyan: "bg-cyan-500/20 text-cyan-400 border-cyan-500/40",
    emerald: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40",
    amber: "bg-amber-500/20 text-amber-400 border-amber-500/40",
    rose: "bg-rose-500/20 text-rose-400 border-rose-500/40",
    purple: "bg-purple-500/20 text-purple-400 border-purple-500/40",
  };

  const badgeStyle = content.badgeColor ? colorMap[content.badgeColor] : colorMap.cyan;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 animate-fadeIn">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-slate-950/80 backdrop-blur-md transition-opacity"
        onClick={onClose}
      />

      {/* Modal Box */}
      <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl text-slate-100">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              <Info className="h-5 w-5" />
            </div>
            <div>
              {content.category && (
                <span className="text-[11px] font-bold uppercase tracking-wider text-cyan-400">
                  {content.category}
                </span>
              )}
              <h2 className="text-xl font-extrabold text-white tracking-tight flex items-center gap-2">
                {content.title}
                {content.badge && (
                  <span className={`rounded-full px-2.5 py-0.5 text-xs font-bold border ${badgeStyle}`}>
                    {content.badge}
                  </span>
                )}
              </h2>
            </div>
          </div>

          <button
            onClick={onClose}
            className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-white transition-all"
            aria-label="Close dialog"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="mt-4 space-y-5 text-xs sm:text-sm">
          {/* Summary */}
          <div className="rounded-xl bg-slate-950/80 p-4 border border-slate-800/80 text-slate-300 leading-relaxed">
            <p>{content.summary}</p>
          </div>

          {/* Formula or Math reference */}
          {content.formula && (
            <div className="rounded-xl bg-slate-950 p-3.5 border border-cyan-500/30 font-mono text-xs text-cyan-300">
              <span className="text-slate-400 font-sans block mb-1 font-semibold text-[11px] uppercase tracking-wider">
                Mathematical Rule / Metric Threshold:
              </span>
              <code>{content.formula}</code>
            </div>
          )}

          {/* Key Concepts / Bullet points */}
          {content.keyPoints && content.keyPoints.length > 0 && (
            <div>
              <h4 className="font-bold text-white text-xs uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <HelpCircle className="h-4 w-4 text-cyan-400" />
                Key Concepts & What It Means
              </h4>
              <ul className="space-y-2 text-slate-300">
                {content.keyPoints.map((pt, idx) => (
                  <li key={idx} className="flex items-start gap-2 bg-slate-950/40 p-2.5 rounded-lg border border-slate-800/60">
                    <span className="text-cyan-400 font-bold mt-0.5">•</span>
                    <span>{pt}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Normal vs Anomaly Comparison */}
          {content.normalVsAnomaly && (
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-3.5">
                <div className="flex items-center gap-1.5 font-bold text-emerald-400 mb-1">
                  <CheckCircle2 className="h-4 w-4" />
                  <span>Normal State</span>
                </div>
                <p className="text-slate-300 text-xs">{content.normalVsAnomaly.normal}</p>
              </div>

              <div className="rounded-xl border border-rose-500/30 bg-rose-950/20 p-3.5">
                <div className="flex items-center gap-1.5 font-bold text-rose-400 mb-1">
                  <AlertTriangle className="h-4 w-4" />
                  <span>Anomalous State</span>
                </div>
                <p className="text-slate-300 text-xs">{content.normalVsAnomaly.anomaly}</p>
              </div>
            </div>
          )}

          {/* How to test */}
          {content.howToTest && (
            <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 p-4">
              <div className="flex items-center gap-2 font-bold text-amber-400 mb-1.5">
                <Lightbulb className="h-4 w-4 text-amber-400" />
                <span>How You Can Test This Right Now</span>
              </div>
              <p className="text-slate-300 text-xs leading-relaxed">{content.howToTest}</p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="mt-6 flex justify-end border-t border-slate-800 pt-4">
          <button
            onClick={onClose}
            className="rounded-xl bg-cyan-600 px-5 py-2 text-xs font-bold text-white hover:bg-cyan-500 transition-all shadow-lg shadow-cyan-500/20"
          >
            Got it, thanks!
          </button>
        </div>
      </div>
    </div>
  );
}
