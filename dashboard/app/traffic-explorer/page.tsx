"use client";

import { useState } from "react";
import Navbar from "@/components/NavBar";
import Footer from "@/components/Footer";
import { useSocket } from "@/hooks/useSocket";
import { Database, Search, ShieldAlert, ShieldCheck, Filter } from "lucide-react";

export default function TrafficExplorerPage() {
  const { events, totalRequests, connected } = useSocket();
  const [searchQuery, setSearchQuery] = useState("");
  const [filterMethod, setFilterMethod] = useState("ALL");
  const [filterThreat, setFilterThreat] = useState("ALL");

  const filteredEvents = events.filter((ev) => {
    const matchesSearch =
      ev.ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ev.path.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ev.user_agent.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesMethod =
      filterMethod === "ALL" || ev.method.toUpperCase() === filterMethod;

    const isAttackerIp =
      ev.ip.startsWith("185.220") ||
      ev.ip.startsWith("45.83") ||
      ev.ip.startsWith("103.21");

    const isAttackPath =
      ev.path.includes("admin") ||
      ev.path.includes(".env") ||
      ev.path.includes("debug") ||
      ev.path.includes("bypass");

    const isAnomaly = isAttackerIp || isAttackPath;

    const matchesThreat =
      filterThreat === "ALL" ||
      (filterThreat === "ANOMALY" && isAnomaly) ||
      (filterThreat === "LEGITIMATE" && !isAnomaly);

    return matchesSearch && matchesMethod && matchesThreat;
  });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500 selection:text-slate-950">
      <Navbar connected={connected} totalRequests={totalRequests} />

      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 space-y-6">
        <div className="border-b border-slate-800 pb-6 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-full bg-cyan-500/10 px-3 py-1 text-xs font-bold text-cyan-400 border border-cyan-500/30 font-mono">
                <Database className="h-3.5 w-3.5 text-cyan-400" />
                SEARCHABLE TELEMETRY EXPLORER
              </span>
            </div>
            <h1 className="mt-2 text-3xl font-black tracking-tight text-white sm:text-4xl">
              HTTP Traffic & Threat Explorer
            </h1>
            <p className="mt-1 text-sm text-slate-400">
              Full-screen searchable telemetry table with real-time threat risk classification and payload inspection.
            </p>
          </div>
        </div>

        {/* Filter Controls */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 backdrop-blur-xl flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-3">
            {/* Method Filter */}
            <div className="flex items-center rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs font-semibold">
              {["ALL", "GET", "POST", "PUT", "DELETE"].map((m) => (
                <button
                  key={m}
                  onClick={() => setFilterMethod(m)}
                  className={`rounded-md px-3 py-1 transition-all ${
                    filterMethod === m
                      ? "bg-cyan-500 text-slate-950 font-bold"
                      : "text-slate-400 hover:text-white"
                  }`}
                >
                  {m}
                </button>
              ))}
            </div>

            {/* Threat Risk Filter */}
            <div className="flex items-center rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs font-semibold">
              {[
                { label: "ALL THREATS", value: "ALL" },
                { label: "ANOMALY", value: "ANOMALY" },
                { label: "LEGITIMATE", value: "LEGITIMATE" },
              ].map((t) => (
                <button
                  key={t.value}
                  onClick={() => setFilterThreat(t.value)}
                  className={`rounded-md px-3 py-1 transition-all ${
                    filterThreat === t.value
                      ? "bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-bold"
                      : "text-slate-400 hover:text-white"
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          {/* Search Bar */}
          <div className="relative w-full sm:w-64">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search IP, Path, User-Agent..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-lg bg-slate-950 border border-slate-800 pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none font-mono"
            />
          </div>
        </div>

        {/* Telemetry Table */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 backdrop-blur-xl shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-slate-800 bg-slate-950/80 font-semibold uppercase tracking-wider text-slate-400 text-[11px] font-mono">
                <tr>
                  <th className="py-3.5 px-4">Time</th>
                  <th className="py-3.5 px-4">Method</th>
                  <th className="py-3.5 px-4">Client Remote IP</th>
                  <th className="py-3.5 px-4">Request Endpoint Path</th>
                  <th className="py-3.5 px-4">Payload Size</th>
                  <th className="py-3.5 px-4">User-Agent</th>
                  <th className="py-3.5 px-4">Threat Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredEvents.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-500 font-sans">
                      No telemetry logs matching query filters.
                    </td>
                  </tr>
                ) : (
                  filteredEvents.map((ev, index) => {
                    const isAttackerIp =
                      ev.ip.startsWith("185.220") ||
                      ev.ip.startsWith("45.83") ||
                      ev.ip.startsWith("103.21");

                    const isAttackPath =
                      ev.path.includes("admin") ||
                      ev.path.includes(".env") ||
                      ev.path.includes("debug") ||
                      ev.path.includes("bypass");

                    return (
                      <tr
                        key={ev.id || index}
                        className={`transition-colors hover:bg-slate-800/40 ${
                          isAttackerIp || isAttackPath ? "bg-rose-950/10" : ""
                        }`}
                      >
                        <td className="py-3.5 px-4 text-slate-400">{ev.time}</td>

                        <td className="py-3.5 px-4">
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

                        <td className="py-3.5 px-4">
                          <span className={isAttackerIp ? "text-rose-400 font-bold" : "text-slate-200"}>
                            {ev.ip}
                          </span>
                          {isAttackerIp && (
                            <span className="ml-2 rounded bg-rose-500/20 px-1.5 py-0.5 text-[9px] font-bold text-rose-300 border border-rose-500/30">
                              BOTNET / TOR
                            </span>
                          )}
                        </td>

                        <td className="py-3.5 px-4 text-slate-300">
                          <span className={isAttackPath ? "text-amber-300 font-bold" : ""}>
                            {ev.path}
                          </span>
                        </td>

                        <td className="py-3.5 px-4 text-slate-400">
                          {ev.content_length ? `${ev.content_length} B` : "0 B"}
                        </td>

                        <td className="py-3.5 px-4 text-slate-400 max-w-xs truncate" title={ev.user_agent}>
                          {ev.user_agent}
                        </td>

                        <td className="py-3.5 px-4">
                          {ev.detection && ev.detection.label !== "Normal" && ev.detection.label !== "Unknown" ? (
                            <span className="inline-flex items-center gap-1 text-[10px] font-bold text-rose-400">
                              <ShieldAlert className="h-3 w-3" /> {ev.detection.label}
                            </span>
                          ) : ev.detection && ev.detection.label === "Normal" ? (
                            <span className="inline-flex items-center gap-1 text-[10px] font-bold text-emerald-400">
                              <ShieldCheck className="h-3 w-3" /> NORMAL
                            </span>
                          ) : isAttackerIp || isAttackPath ? (
                            <span className="inline-flex items-center gap-1 text-[10px] font-bold text-rose-400">
                              <ShieldAlert className="h-3 w-3" /> ANOMALY
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-[10px] font-bold text-emerald-400">
                              <ShieldCheck className="h-3 w-3" /> LEGITIMATE
                            </span>
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
