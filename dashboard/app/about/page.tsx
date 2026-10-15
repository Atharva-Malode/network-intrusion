"use client";

import Navbar from "@/components/NavBar";
import Footer from "@/components/Footer";
import { useSocket } from "@/hooks/useSocket";
import { Radio, Cpu, Activity } from "lucide-react";

export default function AboutPage() {
  const { totalRequests, connected } = useSocket();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
      <Navbar connected={connected} totalRequests={totalRequests} />

      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 space-y-8">
        <div className="border-b border-slate-800 pb-6">
          <h1 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">
            How it works
          </h1>
          <p className="mt-1 text-sm text-slate-400 max-w-3xl">
            Traffic is captured by a reverse proxy, turned into NSL-KDD features, and
            classified by a model plus a signature layer.
          </p>
        </div>

        {/* Pipeline */}
        <div className="grid gap-6 md:grid-cols-3">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-3">
            <div className="rounded-xl bg-cyan-500/10 p-3 w-fit text-cyan-400 border border-cyan-500/30">
              <Radio className="h-6 w-6" />
            </div>
            <h3 className="text-base font-bold text-white">1. Capture proxy</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              A reverse proxy sits in front of the demo site. For every request it
              measures byte counts, timing and sliding-window rate statistics, and
              builds a 41-feature NSL-KDD record.
            </p>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-3">
            <div className="rounded-xl bg-purple-500/10 p-3 w-fit text-purple-400 border border-purple-500/30">
              <Cpu className="h-6 w-6" />
            </div>
            <h3 className="text-base font-bold text-white">2. Two-tier detector</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              A RandomForest trained on NSL-KDD classifies Normal / DoS / Probe. A
              signature layer covers R2L, U2R and volumetric floods the model cannot
              learn. Each verdict is labelled model or signature.
            </p>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-3">
            <div className="rounded-xl bg-emerald-500/10 p-3 w-fit text-emerald-400 border border-emerald-500/30">
              <Activity className="h-6 w-6" />
            </div>
            <h3 className="text-base font-bold text-white">3. Live dashboard</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Verdicts, confidence and drift metrics stream to the dashboard over a
              WebSocket as each request arrives.
            </p>
          </div>
        </div>

        {/* Attack → class mapping */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
          <h2 className="text-base font-bold text-white">Attack scripts and expected class</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-slate-800 bg-slate-950/80 font-mono text-slate-400 uppercase text-[11px]">
                <tr>
                  <th className="py-3 px-4">Script</th>
                  <th className="py-3 px-4">Attack</th>
                  <th className="py-3 px-4">Class</th>
                  <th className="py-3 px-4">Detected by</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                <tr>
                  <td className="py-3.5 px-4 text-white">normal.py</td>
                  <td className="py-3.5 px-4 text-slate-400">Legitimate browsing</td>
                  <td className="py-3.5 px-4"><span className="rounded bg-emerald-500/20 px-2 py-0.5 font-bold text-emerald-400">Normal</span></td>
                  <td className="py-3.5 px-4 text-slate-400">model</td>
                </tr>
                <tr>
                  <td className="py-3.5 px-4 text-white">recon.py</td>
                  <td className="py-3.5 px-4 text-slate-400">Endpoint scanning</td>
                  <td className="py-3.5 px-4"><span className="rounded bg-amber-500/20 px-2 py-0.5 font-bold text-amber-400">Probe</span></td>
                  <td className="py-3.5 px-4 text-slate-400">model</td>
                </tr>
                <tr>
                  <td className="py-3.5 px-4 text-white">flood.py</td>
                  <td className="py-3.5 px-4 text-slate-400">DoS / DDoS flood</td>
                  <td className="py-3.5 px-4"><span className="rounded bg-rose-500/20 px-2 py-0.5 font-bold text-rose-400">DoS</span></td>
                  <td className="py-3.5 px-4 text-slate-400">model / signature</td>
                </tr>
                <tr>
                  <td className="py-3.5 px-4 text-white">credential.py</td>
                  <td className="py-3.5 px-4 text-slate-400">Auth brute force</td>
                  <td className="py-3.5 px-4"><span className="rounded bg-purple-500/20 px-2 py-0.5 font-bold text-purple-400">R2L</span></td>
                  <td className="py-3.5 px-4 text-slate-400">signature</td>
                </tr>
                <tr>
                  <td className="py-3.5 px-4 text-white">exploit.py</td>
                  <td className="py-3.5 px-4 text-slate-400">RCE / traversal</td>
                  <td className="py-3.5 px-4"><span className="rounded bg-fuchsia-500/20 px-2 py-0.5 font-bold text-fuchsia-400">U2R</span></td>
                  <td className="py-3.5 px-4 text-slate-400">signature</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
}
