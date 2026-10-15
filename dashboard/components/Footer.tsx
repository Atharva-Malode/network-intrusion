"use client";

import { Shield } from "lucide-react";

export default function Footer() {
  return (
    <footer className="mt-16 border-t border-slate-800 bg-slate-950/90 px-6 py-6 text-slate-400">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 text-sm">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-cyan-400" />
          <span className="font-semibold text-white">Network Intrusion Detection</span>
        </div>
        <span className="text-xs text-slate-500">Local demo · NSL-KDD model + signature layer</span>
      </div>
    </footer>
  );
}
