"use client";

// Demo sign-in page for the Netflix-clone target site. It exists so the
// credential-abuse (R2L) attack has a realistic auth surface to hit and so the
// walkthrough "feels" complete. The password is a hard-coded demo value — this
// is a throwaway lab site, not a real login.
import { useState } from "react";

const DEMO_USER = "admin";
const DEMO_PASS = "netflix123";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState<null | "ok" | "fail" | "busy">(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus("busy");
    try {
      const r = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      setStatus(r.ok ? "ok" : "fail");
    } catch {
      // fall back to a local check if the API route is unreachable
      setStatus(username === DEMO_USER && password === DEMO_PASS ? "ok" : "fail");
    }
  };

  return (
    <div className="min-h-screen bg-[#141414] text-white flex items-center justify-center px-4">
      <div className="w-full max-w-md rounded-lg bg-black/70 p-8 sm:p-12 shadow-2xl">
        <div className="mb-8 text-3xl font-black tracking-tight text-[#e50914]">NETIFLIX</div>
        <h1 className="mb-6 text-2xl font-bold">Sign In</h1>

        <form onSubmit={submit} className="space-y-4">
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Email or username"
            className="w-full rounded bg-[#333] px-4 py-3 text-sm text-white placeholder-neutral-400 outline-none focus:bg-[#454545]"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
            className="w-full rounded bg-[#333] px-4 py-3 text-sm text-white placeholder-neutral-400 outline-none focus:bg-[#454545]"
          />
          <button
            type="submit"
            disabled={status === "busy"}
            className="w-full rounded bg-[#e50914] py-3 text-sm font-bold text-white hover:brightness-110 disabled:opacity-60"
          >
            {status === "busy" ? "Signing in…" : "Sign In"}
          </button>
        </form>

        {status === "ok" && (
          <p className="mt-4 rounded border border-emerald-600/50 bg-emerald-950/40 px-3 py-2 text-sm text-emerald-300">
            Welcome back — you&apos;re signed in.
          </p>
        )}
        {status === "fail" && (
          <p className="mt-4 rounded border border-rose-600/50 bg-rose-950/40 px-3 py-2 text-sm text-rose-300">
            Incorrect username or password.
          </p>
        )}

        <p className="mt-8 text-xs text-neutral-500">
          Demo site. Use <span className="text-neutral-300">admin</span> /{" "}
          <span className="text-neutral-300">netflix123</span> to sign in.
        </p>
      </div>
    </div>
  );
}
