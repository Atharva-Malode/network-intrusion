"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, Radio, Activity, Gauge, Database, Info, Brain } from "lucide-react";

interface NavBarProps {
  connected?: boolean;
  totalRequests?: number;
}

export default function NavBar({ connected = true, totalRequests = 0 }: NavBarProps) {
  const pathname = usePathname();

  const navLinks = [
    { name: "Dashboard", href: "/", icon: Activity },
    { name: "Monitoring", href: "/monitoring", icon: Radio },
    { name: "Drift", href: "/drift-analysis", icon: Gauge },
    { name: "Traffic", href: "/traffic-explorer", icon: Database },
    { name: "Learning", href: "/learning", icon: Brain },
    { name: "About", href: "/about", icon: Info },
  ];

  return (
    <header className="sticky top-0 z-50 border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-xl">
      <div className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-3 sm:px-6 md:flex-row md:items-center md:justify-between">
        {/* Brand */}
        <Link href="/" className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-base font-bold tracking-wide text-white">
              Network Intrusion <span className="text-cyan-400">Detection</span>
            </h1>
            <p className="text-[11px] text-slate-400">Real-time NIDS demo</p>
          </div>
        </Link>

        {/* Nav */}
        <nav className="flex flex-wrap items-center gap-1.5 rounded-xl bg-slate-900/90 p-1 border border-slate-800">
          {navLinks.map((link) => {
            const Icon = link.icon;
            const isActive = pathname === link.href;
            return (
              <Link
                key={link.name}
                href={link.href}
                className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-all ${
                  isActive
                    ? "bg-cyan-500 text-slate-950"
                    : "text-slate-400 hover:text-white hover:bg-slate-800/60"
                }`}
              >
                <Icon className={`h-3.5 w-3.5 ${isActive ? "text-slate-950" : "text-cyan-400"}`} />
                <span>{link.name}</span>
              </Link>
            );
          })}
        </nav>

        {/* Status */}
        <div className="flex items-center gap-3">
          {totalRequests > 0 && (
            <div className="hidden lg:flex items-center gap-2 rounded-lg bg-slate-900/80 px-3 py-1.5 border border-slate-800 text-xs text-slate-300 font-mono">
              {totalRequests.toLocaleString()} events
            </div>
          )}
          <div className="flex items-center gap-2 rounded-full bg-slate-900 px-3 py-1.5 border border-slate-800 text-xs">
            <Radio className={`h-3.5 w-3.5 ${connected ? "text-emerald-400 animate-pulse" : "text-rose-500"}`} />
            <span className="font-semibold text-[11px]">
              {connected ? (
                <span className="text-emerald-400">Live</span>
              ) : (
                <span className="text-rose-400">Offline</span>
              )}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}
