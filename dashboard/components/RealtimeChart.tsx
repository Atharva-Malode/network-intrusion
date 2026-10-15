"use client";

import { useState } from "react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ReferenceLine,
} from "recharts";
import { Activity, Info } from "lucide-react";
import InfoModal, { ModalInfoContent } from "@/components/InfoModal";

interface RealtimeChartProps {
  data: Array<{
    time: string;
    rps: number;
    threshold: number;
    driftScore: number;
  }>;
}

export default function RealtimeChart({ data }: RealtimeChartProps) {
  const [activeModal, setActiveModal] = useState<ModalInfoContent | null>(null);

  const chartInfo: ModalInfoContent = {
    title: "Real-Time Traffic Rate & Anomaly Timeline",
    category: "Telemetry Visualization",
    badge: "Live Recharts",
    badgeColor: "cyan",
    summary:
      "This chart displays live incoming telemetry throughput measured in Requests Per Second (RPS) plotted against the composite Concept Drift Score % over time.",
    keyPoints: [
      "Cyan Area (Throughput RPS): Displays current volume of HTTP requests hitting the backend server per second.",
      "Rose Area (Drift Score %): Displays the composite percentage index calculated by the ML statistical engine.",
      "Amber Dashed Line (Threat Threshold = 20 RPS): Indicates the volumetric rate limit boundary beyond which traffic spikes trigger rate warnings."
    ],
    normalVsAnomaly: {
      normal: "Cyan curve stays below 20 RPS and Rose curve stays below 25%.",
      anomaly: "Cyan curve spikes sharply above 20 RPS or Rose drift curve climbs towards 100%."
    },
    howToTest: "Browse http://localhost:8080 or run an attack script to see the throughput update live."
  };

  return (
    <>
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-xl shadow-xl">
        <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-cyan-400" />
            <div>
              <h2 className="text-lg font-bold text-white tracking-wide flex items-center gap-2">
                Real-Time Traffic Rate & Anomaly Timeline
                <button
                  onClick={() => setActiveModal(chartInfo)}
                  className="rounded-full p-1 text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition-all"
                  title="Learn about Traffic Timeline"
                >
                  <Info className="h-4 w-4" />
                </button>
              </h2>
              <p className="text-xs text-slate-400">
                Live incoming telemetry throughput (Req/sec) & statistical drift curve
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs font-semibold">
            <div className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-cyan-400"></span>
              <span className="text-slate-300">Throughput (RPS)</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-rose-500"></span>
              <span className="text-slate-300">Drift Score %</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="h-0.5 w-4 bg-amber-400 border border-dashed"></span>
              <span className="text-amber-400">Anomalous Threshold (20 RPS)</span>
            </div>
          </div>
        </div>

        <div className="h-64 w-full">
          {data.length === 0 ? (
            <div className="flex h-full items-center justify-center text-sm text-slate-500">
              Waiting for streaming telemetry data...
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorRps" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.6} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorDrift" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0} />
                  </linearGradient>
                </defs>

                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} domain={[0, 'auto']} />

                <Tooltip
                  contentStyle={{
                    backgroundColor: "#090d16",
                    borderColor: "#334155",
                    borderRadius: "0.75rem",
                    fontSize: "0.75rem",
                    color: "#f8fafc",
                  }}
                />

                <ReferenceLine y={20} stroke="#f59e0b" strokeDasharray="3 3" label={{ value: 'Threat Threshold', fill: '#f59e0b', fontSize: 10, position: 'top' }} />

                <Area
                  type="monotone"
                  dataKey="rps"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorRps)"
                  name="RPS"
                />
                <Area
                  type="monotone"
                  dataKey="driftScore"
                  stroke="#f43f5e"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorDrift)"
                  name="Drift Score %"
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <InfoModal
        isOpen={activeModal !== null}
        onClose={() => setActiveModal(null)}
        content={activeModal}
      />
    </>
  );
}

