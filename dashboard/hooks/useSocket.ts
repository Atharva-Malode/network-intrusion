"use client";

import { useEffect, useState, useRef, useCallback } from "react";

export interface DriftData {
  status: "NORMAL" | "WARNING" | "CRITICAL";
  drift_detected: boolean;
  overall_drift_score: number;
  techniques: {
    ks_test: {
      name: string;
      statistic: number;
      p_value: number;
      drift: boolean;
      score?: number;
      description: string;
    };
    psi: {
      name: string;
      score: number;
      status: string;
      drift: boolean;
      scaled_score?: number;
      description: string;
    };
    wasserstein: {
      name: string;
      distance: number;
      drift: boolean;
      score?: number;
      description: string;
    };
    z_score: {
      name: string;
      score: number;
      drift: boolean;
      scaled_score?: number;
      description: string;
    };
  };
  features: Array<{
    name: string;
    baseline_avg: number;
    current_avg: number;
    drift: boolean;
  }>;
  debug?: {
    psi_contribution: number;
    ks_contribution: number;
    wasserstein_contribution: number;
    z_score_contribution: number;
    psi_raw: number;
    ks_raw_d: number;
    wasserstein_raw_w: number;
    z_score_raw_z: number;
    formula_explanation: string;
    baseline_sample_count: number;
    current_sample_count: number;
  };
}

// The five NSL-KDD classes, plus any class learned live (e.g. "Attack-1").
// `string & {}` accepts learned names while keeping literal autocompletion.
export type AttackClass = "Normal" | "DoS" | "Probe" | "R2L" | "U2R" | "Unknown" | (string & {});

export interface Detection {
  label: AttackClass;
  confidence: number;
  probabilities: Record<string, number>;
  description: string;
  model_loaded?: boolean;
  uncertain?: boolean;
  novel?: boolean;
  outlier?: boolean;
  novelty_score?: number | null;
  source?: "model" | "signature" | "assisted";
  model_label?: AttackClass;
  model_confidence?: number;
  signature?: {
    matched: boolean;
    label?: AttackClass;
    confidence?: number;
    reason?: string;
  };
}

export interface ThreatSummary {
  window_size: number;
  attack_count: number;
  attack_ratio: number;
  dominant_attack: AttackClass | null;
  class_counts: Record<string, number>;
  top_attacker_ips: Array<{ ip: string; count: number }>;
}

const EMPTY_THREAT: ThreatSummary = {
  window_size: 0,
  attack_count: 0,
  attack_ratio: 0,
  dominant_attack: null,
  class_counts: { Normal: 0, DoS: 0, Probe: 0, R2L: 0, U2R: 0 },
  top_attacker_ips: [],
};

export function useSocket() {
  const [events, setEvents] = useState<any[]>([]);
  const [rps, setRps] = useState(0);
  const [totalRequests, setTotalRequests] = useState(0);
  const [uniqueIps, setUniqueIps] = useState(0);
  const [connected, setConnected] = useState(false);
  const [historyData, setHistoryData] = useState<any[]>([]);
  const [detection, setDetection] = useState<Detection | null>(null);
  const [threatSummary, setThreatSummary] = useState<ThreatSummary>(EMPTY_THREAT);
  
  const [drift, setDrift] = useState<DriftData>({
    status: "NORMAL",
    drift_detected: false,
    overall_drift_score: 0,
    techniques: {
      ks_test: { name: "KS-Test", statistic: 0, p_value: 1.0, drift: false, description: "Goodness-of-fit test" },
      psi: { name: "PSI", score: 0, status: "STABLE", drift: false, description: "Distribution stability index" },
      wasserstein: { name: "Wasserstein Distance", distance: 0, drift: false, description: "Earth Mover's Distance" },
      z_score: { name: "Z-Score", score: 0, drift: false, description: "Deviation from baseline mean" },
    },
    features: [],
  });

  const secondCounter = useRef(0);
  const ipSet = useRef(new Set<string>());
  const driftScoreRef = useRef(0);

  // Initial fetch for drift & metrics
  const fetchInitialMetrics = useCallback(async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/metrics");
      if (res.ok) {
        const data = await res.json();
        setTotalRequests(data.total_requests || 0);
        setUniqueIps(data.unique_ips || 0);
        if (data.drift) {
          setDrift(data.drift);
        }
      }
    } catch (err) {
      console.warn("Metrics fetch error:", err);
    }
  }, []);

  // Keep the latest drift score in a ref so the 1s interval can read it WITHOUT
  // making it a dependency of the WebSocket effect below. If it were a dep, every
  // drift update (i.e. every traffic message) would tear the socket down and
  // reconnect — constant flapping that shows the dashboard as "offline".
  useEffect(() => {
    driftScoreRef.current = drift.overall_drift_score;
  }, [drift.overall_drift_score]);

  useEffect(() => {
    fetchInitialMetrics();

    let ws: WebSocket | null = null;
    let reconnectTimeout: NodeJS.Timeout;

    const connectWebSocket = () => {
      ws = new WebSocket("ws://127.0.0.1:8000/ws");

      ws.onopen = () => {
        setConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          if (data.type === "init") {
            setTotalRequests(data.events_count || 0);
            if (data.drift) setDrift(data.drift);
            return;
          }

          if (data.type === "traffic") {
            secondCounter.current += 1;
            setTotalRequests((prev) => prev + 1);
            ipSet.current.add(data.ip);
            setUniqueIps(ipSet.current.size);

            if (data.drift) {
              setDrift(data.drift);
            }

            if (data.detection) {
              setDetection(data.detection);
            }
            if (data.threat_summary) {
              setThreatSummary(data.threat_summary);
            }

            const formattedEvent = {
              id: Math.random().toString(36).substring(2, 9),
              time: new Date(data.timestamp || Date.now()).toLocaleTimeString(),
              path: data.path,
              method: data.method || "GET",
              ip: data.ip,
              content_length: data.content_length || 0,
              user_agent: data.user_agent || "Unknown",
              status: data.status ?? null,
              detection: data.detection || null,
            };

            setEvents((prev) => [formattedEvent, ...prev].slice(0, 30));
          }
        } catch (e) {
          console.error("WS message parse error:", e);
        }
      };

      ws.onclose = () => {
        setConnected(false);
        reconnectTimeout = setTimeout(connectWebSocket, 3000);
      };

      ws.onerror = () => {
        setConnected(false);
      };
    };

    connectWebSocket();

    // 1-second interval to compute RPS and push to time-series chart
    const interval = setInterval(() => {
      const currentRps = secondCounter.current;
      setRps(currentRps);
      secondCounter.current = 0;

      const timeStr = new Date().toLocaleTimeString();
      setHistoryData((prev) => {
        const next = [
          ...prev,
          {
            time: timeStr,
            rps: currentRps,
            threshold: 20,
            driftScore: driftScoreRef.current,
          },
        ];
        return next.slice(-25); // Keep last 25 time ticks
      });
    }, 1000);

    return () => {
      clearInterval(interval);
      clearTimeout(reconnectTimeout);
      if (ws) ws.close();
    };
  }, [fetchInitialMetrics]);

  return {
    events,
    rps,
    totalRequests,
    uniqueIps,
    connected,
    drift,
    detection,
    threatSummary,
    historyData,
  };
}