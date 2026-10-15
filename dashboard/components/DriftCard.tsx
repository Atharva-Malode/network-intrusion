"use client";

import { useState } from "react";
import { DriftData } from "@/hooks/useSocket";
import { AlertTriangle, CheckCircle2, Flame, Gauge, Info, Layers, ChevronDown, ChevronUp, Calculator, Activity, ShieldCheck, ShieldAlert } from "lucide-react";
import InfoModal, { ModalInfoContent } from "@/components/InfoModal";

interface DriftCardProps {
  drift: DriftData;
}

export default function DriftCard({ drift }: DriftCardProps) {
  const { status, drift_detected, overall_drift_score, techniques, features, debug } = drift;
  const [activeModalContent, setActiveModalContent] = useState<ModalInfoContent | null>(null);
  const [showDebug, setShowDebug] = useState(false);

  const getStatusBanner = () => {
    switch (status) {
      case "CRITICAL":
        return (
          <div className="flex items-center justify-between rounded-xl bg-gradient-to-r from-rose-950/80 via-rose-900/40 to-slate-950 p-4 border border-rose-500/50 shadow-lg shadow-rose-500/10">
            <div className="flex items-center gap-3">
              <div className="rounded-xl bg-rose-500/20 p-2.5 border border-rose-500/40 text-rose-400 animate-pulse">
                <Flame className="h-6 w-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-black text-rose-400 tracking-wider uppercase font-mono">
                    THREAT STATUS: CRITICAL
                  </span>
                  <span className="rounded bg-rose-500/20 px-2 py-0.5 text-[10px] font-extrabold text-rose-300 border border-rose-500/30">
                    SCORE &gt; 60%
                  </span>
                </div>
                <p className="text-xs text-rose-200/80 mt-0.5">
                  High probability cyber attack or major statistical traffic divergence detected.
                </p>
              </div>
            </div>
            <div className="hidden sm:block text-right font-mono">
              <div className="text-2xl font-black text-rose-400">{overall_drift_score.toFixed(1)}%</div>
              <div className="text-[10px] text-rose-300 uppercase tracking-widest">CRITICAL DRIFT</div>
            </div>
          </div>
        );
      case "WARNING":
        return (
          <div className="flex items-center justify-between rounded-xl bg-gradient-to-r from-amber-950/80 via-amber-900/40 to-slate-950 p-4 border border-amber-500/50 shadow-lg shadow-amber-500/10">
            <div className="flex items-center gap-3">
              <div className="rounded-xl bg-amber-500/20 p-2.5 border border-amber-500/40 text-amber-400">
                <AlertTriangle className="h-6 w-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-black text-amber-400 tracking-wider uppercase font-mono">
                    THREAT STATUS: WARNING
                  </span>
                  <span className="rounded bg-amber-500/20 px-2 py-0.5 text-[10px] font-extrabold text-amber-300 border border-amber-500/30">
                    20% - 60% DRIFT
                  </span>
                </div>
                <p className="text-xs text-amber-200/80 mt-0.5">
                  Moderate distribution shift detected in API endpoint patterns or IP velocities. Monitoring active traffic stream.
                </p>
              </div>
            </div>
            <div className="hidden sm:block text-right font-mono">
              <div className="text-2xl font-black text-amber-400">{overall_drift_score.toFixed(1)}%</div>
              <div className="text-[10px] text-amber-300 uppercase tracking-widest">MODERATE DRIFT</div>
            </div>
          </div>
        );
      default:
        return (
          <div className="flex items-center justify-between rounded-xl bg-gradient-to-r from-emerald-950/60 via-slate-900/60 to-slate-950 p-4 border border-emerald-500/30 shadow-md">
            <div className="flex items-center gap-3">
              <div className="rounded-xl bg-emerald-500/20 p-2.5 border border-emerald-500/40 text-emerald-400">
                <CheckCircle2 className="h-6 w-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-black text-emerald-400 tracking-wider uppercase font-mono">
                    THREAT STATUS: NORMAL
                  </span>
                  <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-[10px] font-extrabold text-emerald-300 border border-emerald-500/30">
                    SCORE 0% - 20%
                  </span>
                </div>
                <p className="text-xs text-slate-300 mt-0.5">
                  Incoming telemetry matches legitimate baseline user browsing behavior. Statistical hypothesis distributions are stable.
                </p>
              </div>
            </div>
            <div className="hidden sm:block text-right font-mono">
              <div className="text-2xl font-black text-emerald-400">{overall_drift_score.toFixed(1)}%</div>
              <div className="text-[10px] text-emerald-400 uppercase tracking-widest">STABLE TRAFFIC</div>
            </div>
          </div>
        );
    }
  };

  const modalInfos: Record<string, ModalInfoContent> = {
    overall: {
      title: "Concept Drift Engine",
      category: "ML Concept Drift Engine",
      badge: status,
      badgeColor: status === "CRITICAL" ? "rose" : status === "WARNING" ? "amber" : "emerald",
      summary:
        "Statistical concept drift occurs when incoming live telemetry distribution diverges from historical clean baseline behavior. The engine aggregates 4 calibrated ML hypothesis techniques.",
      keyPoints: [
        "1. Population Stability Index (30% Weight): Measures path, method, and threat-IP class frequency shifts with Laplace smoothing.",
        "2. Kolmogorov-Smirnov Test (25% Weight): 2-sample continuous feature test evaluating ECDF differences (D > 0.35, p < 0.001).",
        "3. Wasserstein Distance / EMD (25% Weight): Earth Mover's Distance across normalized feature geometry.",
        "4. Z-Score Anomaly (20% Weight): 3-Sigma statistical shift in request rates and payload depth."
      ],
      normalVsAnomaly: {
        normal: "Score 0 - 20%. Standard browsing behavior across typical endpoints.",
        anomaly: "Score 20 - 60% (WARNING) or 60 - 100% (CRITICAL). Automated attack tools, scrapers, or DDoS botnets."
      },
      howToTest: "Run `python main.py flood` from the attack-script to watch the score rise."
    },
    ks_test: {
      title: "Kolmogorov-Smirnov Test (KS-Test)",
      category: "Continuous Distribution Hypothesis Test",
      badge: techniques.ks_test.drift ? "DRIFT DETECTED" : "STABLE",
      badgeColor: techniques.ks_test.drift ? "rose" : "emerald",
      summary:
        "Evaluates maximum empirical cumulative distribution function (ECDF) distance (D-statistic) between baseline numerical features and current streaming traffic window.",
      formula: "Reject H0 if D > 0.35 and p-value < 0.001",
      keyPoints: [
        "D-statistic: Maximum vertical distance between cumulative probability curves.",
        "p-value: Probability that observed distribution difference occurred by random chance."
      ],
      howToTest: "Run `python main.py flood` to shift the traffic distribution."
    },
    psi: {
      title: "Population Stability Index (PSI)",
      category: "Categorical Frequency Shift Metric",
      badge: techniques.psi.status,
      badgeColor: techniques.psi.drift ? "rose" : "emerald",
      summary:
        "Calculates categorical stability across HTTP paths, HTTP methods (GET/POST), and IP Threat Classes using Laplace smoothing.",
      formula: "PSI = Σ (Actual% - Expected%) × ln(Actual% / Expected%)",
      keyPoints: [
        "PSI < 0.10: Stable distribution (0-15 score).",
        "0.10 <= PSI < 0.25: Moderate population shift (15-60 score).",
        "PSI >= 0.25: Severe distribution drift (60-100 score)."
      ],
      howToTest: "Run `python main.py recon` to send scanning paths and trigger a PSI shift."
    },
    wasserstein: {
      title: "Wasserstein Distance (Earth Mover's Distance)",
      category: "Feature Geometry Distance",
      badge: techniques.wasserstein.drift ? "HIGH DISTANCE" : "NORMAL",
      badgeColor: techniques.wasserstein.drift ? "amber" : "emerald",
      summary:
        "Computes minimal work required to transform current feature distribution geometry into the reference baseline distribution.",
      formula: "EMD = ∫ |F_baseline(x) - F_current(x)| dx",
      keyPoints: [
        "Feature Normalization: Path depth, query param count, and content length are z-normalized before EMD computation.",
        "Smooth Continuity: Provides geometric drift distance even when distributions do not overlap."
      ]
    },
    z_score: {
      title: "Z-Score Throughput Anomaly",
      category: "3-Sigma Rate Standard Deviation",
      badge: techniques.z_score.drift ? "ANOMALY" : "STABLE",
      badgeColor: techniques.z_score.drift ? "rose" : "emerald",
      summary:
        "Measures standard deviation variance (|Z|) of incoming Requests Per Second (RPS) and path depths against moving baseline average.",
      formula: "Z = |Current_Value - Mean_Baseline| / Standard_Deviation_Baseline",
      keyPoints: [
        "|Z| < 1.5: Within standard variance.",
        "|Z| >= 3.0: 3-Sigma statistical anomaly (Volumetric DDoS or script burst)."
      ]
    }
  };

  return (
    <>
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 backdrop-blur-xl shadow-xl space-y-6">
        {/* Header & Title */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <Gauge className="h-5 w-5 text-cyan-400" />
              <h2 className="text-lg font-bold text-white tracking-wide flex items-center gap-2">
                Concept Drift (secondary signal)
                <button
                  onClick={() => setActiveModalContent(modalInfos.overall)}
                  className="rounded-full p-1 text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition-all"
                  title="Learn about the concept drift engine"
                >
                  <Info className="h-4 w-4" />
                </button>
              </h2>
            </div>
            <p className="mt-0.5 text-xs text-slate-400">
              Calibrated multi-technique statistical hypothesis monitoring engine
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowDebug(!showDebug)}
              className="flex items-center gap-1.5 rounded-lg bg-slate-950 border border-slate-800 px-3 py-1.5 text-xs font-semibold text-cyan-400 hover:bg-slate-800 transition-all"
            >
              <Calculator className="h-3.5 w-3.5" />
              <span>{showDebug ? "Hide Math Debug" : "Show Math Debug"}</span>
              {showDebug ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>

        {/* Threat Status Banner */}
        {getStatusBanner()}

        {/* Composite Drift Index Progress Gauge */}
        <div className="rounded-xl bg-slate-950/80 p-5 border border-slate-800/80 space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-slate-300 flex items-center gap-1.5">
              Composite Drift Score Gauge:
              <span className="text-[11px] text-slate-500 font-normal">
                (Normal: 0-20% | Warning: 20-60% | Critical: 60-100%)
              </span>
            </span>
            <span
              className={`font-mono text-base font-black ${
                overall_drift_score > 60
                  ? "text-rose-400"
                  : overall_drift_score > 20
                  ? "text-amber-400"
                  : "text-emerald-400"
              }`}
            >
              {overall_drift_score.toFixed(1)}%
            </span>
          </div>

          {/* Calibrated Bar */}
          <div className="relative h-4 w-full overflow-hidden rounded-full bg-slate-900 border border-slate-800 p-0.5">
            <div
              className={`h-full transition-all duration-500 rounded-full ${
                overall_drift_score > 60
                  ? "bg-gradient-to-r from-amber-500 via-rose-500 to-rose-600 shadow-lg shadow-rose-500/50"
                  : overall_drift_score > 20
                  ? "bg-gradient-to-r from-emerald-500 via-cyan-500 to-amber-500"
                  : "bg-gradient-to-r from-emerald-600 to-emerald-400"
              }`}
              style={{ width: `${Math.max(4, overall_drift_score)}%` }}
            />
          </div>

          <div className="flex justify-between text-[10px] font-mono text-slate-500 pt-0.5">
            <span>0% (CLEAN)</span>
            <span>20% (WARNING THRESHOLD)</span>
            <span>60% (CRITICAL THRESHOLD)</span>
            <span>100% (SEVERE ATTACK)</span>
          </div>
        </div>

        {/* Mathematical Debug Breakdown Card (Accordion) */}
        {showDebug && debug && (
          <div className="rounded-xl bg-slate-950/90 p-5 border border-cyan-500/30 space-y-3 font-mono text-xs animate-in fade-in duration-200">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="font-bold text-cyan-400 flex items-center gap-2">
                <Calculator className="h-4 w-4" />
                MATHEMATICAL DRIFT SCORE BREAKDOWN
              </span>
              <span className="text-[10px] text-slate-400">
                Baseline: {debug.baseline_sample_count} ev | Current: {debug.current_sample_count} ev
              </span>
            </div>

            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800 text-[11px] text-slate-300">
              <div className="text-slate-400 text-[10px] uppercase font-sans tracking-wider mb-1">Composite Formula:</div>
              <code className="text-cyan-300 font-bold">{debug.formula_explanation}</code>
            </div>

            <div className="grid gap-3 sm:grid-cols-4 pt-1">
              <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                <div className="text-[10px] text-slate-400 font-sans">1. PSI (30% Weight)</div>
                <div className="text-sm font-bold text-white mt-0.5">+{debug.psi_contribution.toFixed(1)} pts</div>
                <div className="text-[10px] text-slate-500">Raw PSI: {debug.psi_raw.toFixed(4)}</div>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                <div className="text-[10px] text-slate-400 font-sans">2. KS-Test (25% Weight)</div>
                <div className="text-sm font-bold text-white mt-0.5">+{debug.ks_contribution.toFixed(1)} pts</div>
                <div className="text-[10px] text-slate-500">Max D-stat: {debug.ks_raw_d.toFixed(4)}</div>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                <div className="text-[10px] text-slate-400 font-sans">3. EMD (25% Weight)</div>
                <div className="text-sm font-bold text-white mt-0.5">+{debug.wasserstein_contribution.toFixed(1)} pts</div>
                <div className="text-[10px] text-slate-500">Norm Dist: {debug.wasserstein_raw_w.toFixed(4)}</div>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                <div className="text-[10px] text-slate-400 font-sans">4. Z-Score (20% Weight)</div>
                <div className="text-sm font-bold text-white mt-0.5">+{debug.z_score_contribution.toFixed(1)} pts</div>
                <div className="text-[10px] text-slate-500">Max |Z|: {debug.z_score_raw_z.toFixed(2)}</div>
              </div>
            </div>
          </div>
        )}

        {/* 4 Statistical Techniques Cards */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {/* 1. KS-Test */}
          <div
            className={`rounded-xl border p-4 transition-all relative ${
              techniques.ks_test.drift
                ? "border-rose-500/50 bg-rose-950/20"
                : "border-slate-800 bg-slate-950/40"
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-200 flex items-center gap-1">
                KS-Test
                <button
                  onClick={() => setActiveModalContent(modalInfos.ks_test)}
                  className="text-slate-400 hover:text-cyan-400"
                >
                  <Info className="h-3.5 w-3.5" />
                </button>
              </span>
              <span
                className={`rounded px-2 py-0.5 text-[10px] font-extrabold ${
                  techniques.ks_test.drift ? "bg-rose-500/20 text-rose-400" : "bg-emerald-500/20 text-emerald-400"
                }`}
              >
                {techniques.ks_test.drift ? "DRIFT" : "STABLE"}
              </span>
            </div>

            <div className="mt-3 font-mono">
              <div className="text-lg font-black text-white">
                D = {techniques.ks_test.statistic.toFixed(4)}
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                p-value: <span className="text-cyan-300">{techniques.ks_test.p_value.toFixed(4)}</span>
              </div>
            </div>
            <p className="mt-2 text-[10px] text-slate-500 leading-tight">
              {techniques.ks_test.description}
            </p>
          </div>

          {/* 2. Population Stability Index (PSI) */}
          <div
            className={`rounded-xl border p-4 transition-all relative ${
              techniques.psi.drift
                ? "border-amber-500/50 bg-amber-950/20"
                : "border-slate-800 bg-slate-950/40"
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-200 flex items-center gap-1">
                PSI (Categorical)
                <button
                  onClick={() => setActiveModalContent(modalInfos.psi)}
                  className="text-slate-400 hover:text-cyan-400"
                >
                  <Info className="h-3.5 w-3.5" />
                </button>
              </span>
              <span
                className={`rounded px-2 py-0.5 text-[10px] font-extrabold ${
                  techniques.psi.drift ? "bg-rose-500/20 text-rose-400" : "bg-emerald-500/20 text-emerald-400"
                }`}
              >
                {techniques.psi.status}
              </span>
            </div>

            <div className="mt-3 font-mono">
              <div className="text-lg font-black text-white">
                {techniques.psi.score.toFixed(4)}
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Status: <span className="text-cyan-300">{techniques.psi.status}</span>
              </div>
            </div>
            <p className="mt-2 text-[10px] text-slate-500 leading-tight">
              {techniques.psi.description}
            </p>
          </div>

          {/* 3. Wasserstein Distance (EMD) */}
          <div
            className={`rounded-xl border p-4 transition-all relative ${
              techniques.wasserstein.drift
                ? "border-rose-500/50 bg-rose-950/20"
                : "border-slate-800 bg-slate-950/40"
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-200 flex items-center gap-1">
                Wasserstein (EMD)
                <button
                  onClick={() => setActiveModalContent(modalInfos.wasserstein)}
                  className="text-slate-400 hover:text-cyan-400"
                >
                  <Info className="h-3.5 w-3.5" />
                </button>
              </span>
              <span
                className={`rounded px-2 py-0.5 text-[10px] font-extrabold ${
                  techniques.wasserstein.drift ? "bg-amber-500/20 text-amber-400" : "bg-emerald-500/20 text-emerald-400"
                }`}
              >
                {techniques.wasserstein.drift ? "HIGH DIST" : "STABLE"}
              </span>
            </div>

            <div className="mt-3 font-mono">
              <div className="text-lg font-black text-white">
                {techniques.wasserstein.distance.toFixed(4)}
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Earth Mover Distance
              </div>
            </div>
            <p className="mt-2 text-[10px] text-slate-500 leading-tight">
              {techniques.wasserstein.description}
            </p>
          </div>

          {/* 4. Z-Score Anomaly */}
          <div
            className={`rounded-xl border p-4 transition-all relative ${
              techniques.z_score.drift
                ? "border-rose-500/50 bg-rose-950/20"
                : "border-slate-800 bg-slate-950/40"
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-200 flex items-center gap-1">
                Z-Score Anomaly
                <button
                  onClick={() => setActiveModalContent(modalInfos.z_score)}
                  className="text-slate-400 hover:text-cyan-400"
                >
                  <Info className="h-3.5 w-3.5" />
                </button>
              </span>
              <span
                className={`rounded px-2 py-0.5 text-[10px] font-extrabold ${
                  techniques.z_score.drift ? "bg-rose-500/20 text-rose-400" : "bg-emerald-500/20 text-emerald-400"
                }`}
              >
                {techniques.z_score.drift ? "ANOMALY" : "STABLE"}
              </span>
            </div>

            <div className="mt-3 font-mono">
              <div className="text-lg font-black text-white">
                Z = {techniques.z_score.score.toFixed(2)}
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Variance: <span className="text-cyan-300">|Z| &ge; 3.0</span>
              </div>
            </div>
            <p className="mt-2 text-[10px] text-slate-500 leading-tight">
              {techniques.z_score.description}
            </p>
          </div>
        </div>

        {/* Feature Shift Comparison Table */}
        {features && features.length > 0 && (
          <div className="border-t border-slate-800/80 pt-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-1.5">
              <Layers className="h-3.5 w-3.5 text-cyan-400" />
              Feature-Level Shift Diagnostics
            </h3>
            <div className="grid gap-3 sm:grid-cols-3">
              {features.map((feat, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between rounded-lg bg-slate-950/60 p-3 border border-slate-800/60 text-xs"
                >
                  <div>
                    <div className="font-semibold text-slate-200">{feat.name}</div>
                    <div className="text-[11px] text-slate-400 mt-0.5 font-mono">
                      Base: <span className="text-slate-300">{feat.baseline_avg}</span> | Curr:{" "}
                      <span className="text-cyan-300">{feat.current_avg}</span>
                    </div>
                  </div>
                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                      feat.drift ? "bg-rose-500/20 text-rose-400" : "bg-emerald-500/20 text-emerald-400"
                    }`}
                  >
                    {feat.drift ? "SHIFT" : "OK"}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <InfoModal
        isOpen={activeModalContent !== null}
        onClose={() => setActiveModalContent(null)}
        content={activeModalContent}
      />
    </>
  );
}
