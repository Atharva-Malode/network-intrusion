"use client";

import Navbar from "@/components/NavBar";
import Footer from "@/components/Footer";
import DriftCard from "@/components/DriftCard";
import { useSocket } from "@/hooks/useSocket";
import { Gauge, Calculator, Layers, HelpCircle } from "lucide-react";

export default function DriftAnalysisPage() {
  const { totalRequests, connected, drift } = useSocket();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500 selection:text-slate-950">
      <Navbar connected={connected} totalRequests={totalRequests} />

      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 space-y-8">
        <div className="border-b border-slate-800 pb-6 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-full bg-cyan-500/10 px-3 py-1 text-xs font-bold text-cyan-400 border border-cyan-500/30 font-mono">
                <Gauge className="h-3.5 w-3.5 text-cyan-400" />
                STATISTICAL DIAGNOSTIC INSPECTOR
              </span>
            </div>
            <h1 className="mt-2 text-3xl font-black tracking-tight text-white sm:text-4xl">
              Concept Drift Statistical Diagnostics
            </h1>
            <p className="mt-1 text-sm text-slate-400">
              Deep-dive hypothesis testing breakdowns across Population Stability Index (PSI), Kolmogorov-Smirnov (KS) Test, Wasserstein Earth Mover's Distance (EMD), and 3-Sigma Z-Scores.
            </p>
          </div>
        </div>

        <DriftCard drift={drift} />

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 backdrop-blur-xl space-y-4">
          <h2 className="text-lg font-bold text-white tracking-wide flex items-center gap-2 font-mono">
            <Calculator className="h-5 w-5 text-cyan-400" />
            Composite Concept Drift Score Formula
          </h2>
          <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 font-mono text-sm text-cyan-300">
            Composite Score (%) = 30% × S<sub>PSI</sub> + 25% × S<sub>KS</sub> + 25% × S<sub>EMD</sub> + 20% × S<sub>Z</sub>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 text-xs text-slate-300">
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
              <div className="font-bold text-white uppercase tracking-wider font-mono">1. Population Stability Index (PSI)</div>
              <p className="text-slate-400 leading-relaxed">
                Calculated on HTTP paths, HTTP methods, and IP threat classes using Laplace smoothing (k=0.5) to prevent zero-count probability explosions.
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
              <div className="font-bold text-white uppercase tracking-wider font-mono">2. Kolmogorov-Smirnov Test (KS-Test)</div>
              <p className="text-slate-400 leading-relaxed">
                Non-parametric 2-sample cumulative distribution test evaluating D-statistic with continuous jitter smoothing (D &gt; 0.35, p &lt; 0.001).
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
              <div className="font-bold text-white uppercase tracking-wider font-mono">3. Wasserstein Distance (EMD)</div>
              <p className="text-slate-400 leading-relaxed">
                Earth Mover's Distance computed across z-normalized continuous feature dimensions (path depth, query count, content length).
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
              <div className="font-bold text-white uppercase tracking-wider font-mono">4. Z-Score Anomaly Shift</div>
              <p className="text-slate-400 leading-relaxed">
                Standard deviation shift (|Z| &ge; 3.0) comparing current window throughput RPS and average path depth against moving baseline statistics.
              </p>
            </div>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
}
