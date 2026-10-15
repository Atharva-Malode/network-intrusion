"use client";

import Navbar from "@/components/NavBar";
import Footer from "@/components/Footer";
import RealtimeChart from "@/components/RealtimeChart";
import ThreatClassificationCard from "@/components/ThreatClassificationCard";
import { useSocket } from "@/hooks/useSocket";
import { Radio, Activity, Zap, Server, Shield } from "lucide-react";

export default function MonitoringPage() {
  const { rps, totalRequests, uniqueIps, connected, drift, detection, threatSummary, historyData } = useSocket();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500 selection:text-slate-950">
      <Navbar connected={connected} totalRequests={totalRequests} />

      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 space-y-8">
        <div className="border-b border-slate-800 pb-6 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-full bg-cyan-500/10 px-3 py-1 text-xs font-bold text-cyan-400 border border-cyan-500/30 font-mono">
                <Radio className="h-3.5 w-3.5 animate-pulse text-cyan-400" />
                REAL-TIME STREAM MONITORING
              </span>
            </div>
            <h1 className="mt-2 text-3xl font-black tracking-tight text-white sm:text-4xl">
              Telemetry Stream & Throughput Analytics
            </h1>
            <p className="mt-1 text-sm text-slate-400">
              Live HTTP ingestion velocity, Requests Per Second (RPS) timeline, and network stream bandwidth metrics.
            </p>
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-3">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 backdrop-blur-xl font-mono">
            <div className="text-xs text-slate-400 uppercase font-sans font-bold">Current Ingestion Rate</div>
            <div className="text-3xl font-black text-white mt-2">{rps} <span className="text-sm font-normal text-slate-400">RPS</span></div>
            <div className="text-xs text-cyan-400 mt-1">Live WebSocket Feed</div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 backdrop-blur-xl font-mono">
            <div className="text-xs text-slate-400 uppercase font-sans font-bold">Total Telemetry Counter</div>
            <div className="text-3xl font-black text-purple-400 mt-2">{totalRequests.toLocaleString()}</div>
            <div className="text-xs text-slate-400 mt-1">Proxy Sensor Events Ingested</div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 backdrop-blur-xl font-mono">
            <div className="text-xs text-slate-400 uppercase font-sans font-bold">NIDS Model Verdict</div>
            <div className={`text-3xl font-black mt-2 ${
              detection && detection.label !== "Normal" && detection.label !== "Unknown"
                ? "text-rose-400"
                : "text-emerald-400"
            }`}>
              {detection?.label ?? "—"}
            </div>
            <div className="text-xs text-slate-400 mt-1">
              {threatSummary.dominant_attack ? `Dominant: ${threatSummary.dominant_attack}` : "No active threat"}
            </div>
          </div>
        </div>

        <ThreatClassificationCard detection={detection} threatSummary={threatSummary} />

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 backdrop-blur-xl">
          <RealtimeChart data={historyData} />
        </div>
      </main>

      <Footer />
    </div>
  );
}
