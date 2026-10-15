"use client";

import { useState } from "react";
import Navbar from "@/components/NavBar";
import Footer from "@/components/Footer";
import DriftCard from "@/components/DriftCard";
import RealtimeChart from "@/components/RealtimeChart";
import ThreatClassificationCard from "@/components/ThreatClassificationCard";
import ExplainButton from "@/components/ExplainButton";
import { useSocket } from "@/hooks/useSocket";
import { Activity, Globe, Cpu, Shield, ShieldAlert, Search, type LucideIcon } from "lucide-react";

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  accentColor = "cyan",
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  accentColor?: "cyan" | "emerald" | "amber" | "rose" | "purple";
}) {
  const colorMap = {
    cyan: "text-cyan-400 bg-cyan-500/10 border-cyan-500/30",
    emerald: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
    amber: "text-amber-400 bg-amber-500/10 border-amber-500/30",
    rose: "text-rose-400 bg-rose-500/10 border-rose-500/30",
    purple: "text-purple-400 bg-purple-500/10 border-purple-500/30",
  };

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">
          {title}
        </span>
        <div className={`rounded-xl border p-2.5 ${colorMap[accentColor]}`}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      <div className="mt-3 text-3xl font-bold text-white font-mono">{value}</div>
      {subtitle && <p className="mt-1 text-xs text-slate-400">{subtitle}</p>}
    </div>
  );
}

export default function Home() {
  const {
    events,
    rps,
    totalRequests,
    uniqueIps,
    connected,
    drift,
    detection,
    threatSummary,
    historyData,
  } = useSocket();

  const [searchQuery, setSearchQuery] = useState("");
  const [filterMethod, setFilterMethod] = useState("ALL");

  const isThreat =
    detection && detection.label !== "Normal" && detection.label !== "Unknown";

  const filteredEvents = events.filter((ev) => {
    const matchesSearch =
      ev.ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ev.path.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ev.user_agent.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesMethod =
      filterMethod === "ALL" || ev.method.toUpperCase() === filterMethod;
    return matchesSearch && matchesMethod;
  });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
      <Navbar connected={connected} totalRequests={totalRequests} />

      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 space-y-8">
        <div className="flex flex-col gap-4 border-b border-slate-800 pb-6 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">
              Network Intrusion Detection
            </h1>
            <p className="mt-1 text-sm text-slate-400">
              Live HTTP traffic classified by an NSL-KDD model + signature layer. Run
              the attack scripts to generate traffic.
            </p>
          </div>
          <ExplainButton detection={detection} threatSummary={threatSummary} drift={drift} />
        </div>

        {/* Stat cards */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard
            title="Requests / sec"
            value={rps}
            subtitle={rps > 20 ? "High traffic" : "Normal"}
            icon={Activity}
            accentColor={rps > 20 ? "amber" : "cyan"}
          />
          <StatCard
            title="Total events"
            value={totalRequests.toLocaleString()}
            subtitle="Captured via capture proxy"
            icon={Cpu}
            accentColor="purple"
          />
          <StatCard
            title="Unique IPs"
            value={uniqueIps}
            subtitle="Distinct source addresses"
            icon={Globe}
            accentColor="emerald"
          />
          <StatCard
            title="Current verdict"
            value={detection?.label ?? "—"}
            subtitle={
              threatSummary.dominant_attack
                ? `Dominant: ${threatSummary.dominant_attack}`
                : "No active threat"
            }
            icon={isThreat ? ShieldAlert : Shield}
            accentColor={isThreat ? "rose" : "emerald"}
          />
        </div>

        {/* Attack classification */}
        <ThreatClassificationCard detection={detection} threatSummary={threatSummary} />

        {/* Drift (secondary signal) */}
        <DriftCard drift={drift} />

        {/* Throughput timeline */}
        <RealtimeChart data={historyData} />

        {/* Live traffic table */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-slate-800 pb-4 mb-4">
            <div>
              <h2 className="text-lg font-bold text-white">Live traffic</h2>
              <p className="text-xs text-slate-400">
                Per-request verdict from the capture proxy stream
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs font-semibold">
                {["ALL", "GET", "POST", "PUT", "DELETE"].map((m) => (
                  <button
                    key={m}
                    onClick={() => setFilterMethod(m)}
                    className={`rounded-md px-2.5 py-1 transition-all ${
                      filterMethod === m
                        ? "bg-cyan-500 text-slate-950 font-bold"
                        : "text-slate-400 hover:text-white"
                    }`}
                  >
                    {m}
                  </button>
                ))}
              </div>
              <div className="relative">
                <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
                <input
                  type="text"
                  placeholder="Filter IP or path…"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="rounded-lg bg-slate-950 border border-slate-800 pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none w-48 font-mono"
                />
              </div>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-slate-800 bg-slate-950/80 uppercase tracking-wider text-slate-400 text-[11px] font-mono">
                <tr>
                  <th className="py-3 px-4">Time</th>
                  <th className="py-3 px-4">Method</th>
                  <th className="py-3 px-4">Client IP</th>
                  <th className="py-3 px-4">Path</th>
                  <th className="py-3 px-4">Size</th>
                  <th className="py-3 px-4">Verdict</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredEvents.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500 font-sans">
                      No traffic yet. Browse http://localhost:8080 or run an attack script.
                    </td>
                  </tr>
                ) : (
                  filteredEvents.map((ev, index) => {
                    const verdict = ev.detection?.label as string | undefined;
                    const isAttack =
                      verdict && verdict !== "Normal" && verdict !== "Unknown";
                    return (
                      <tr
                        key={ev.id || index}
                        className={`transition-colors hover:bg-slate-800/40 ${
                          isAttack ? "bg-rose-950/10" : ""
                        }`}
                      >
                        <td className="py-3 px-4 text-slate-400">{ev.time}</td>
                        <td className="py-3 px-4">
                          <span
                            className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                              ev.method === "POST"
                                ? "bg-purple-500/20 text-purple-400 border border-purple-500/30"
                                : ev.method === "GET"
                                ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
                                : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                            }`}
                          >
                            {ev.method}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-slate-200">{ev.ip}</td>
                        <td className="py-3 px-4 text-slate-300">{ev.path}</td>
                        <td className="py-3 px-4 text-slate-400">
                          {ev.content_length ? `${ev.content_length} B` : "0 B"}
                        </td>
                        <td className="py-3 px-4">
                          {isAttack ? (
                            <span className="inline-flex items-center gap-1 text-[10px] font-bold text-rose-400">
                              <ShieldAlert className="h-3 w-3" /> {verdict}
                            </span>
                          ) : verdict === "Normal" ? (
                            <span className="text-[10px] font-bold text-emerald-400">NORMAL</span>
                          ) : (
                            <span className="text-[10px] text-slate-500">—</span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
}
