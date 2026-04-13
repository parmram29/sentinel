import React, { useState } from "react";
import { Shield, Loader2, AlertTriangle } from "lucide-react";
import { supabase } from "../lib/supabase";

interface AuthGateProps {
  onAuth: () => void;
}

export default function AuthGate({ onAuth }: AuthGateProps) {
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    setMessage(null);

    if (mode === "login") {
      const { error } = await supabase.auth.signInWithPassword({
        email,
        password,
      });
      if (error) {
        setError(error.message);
      } else {
        onAuth();
      }
    } else {
      const { error } = await supabase.auth.signUp({ email, password });
      if (error) {
        setError(error.message);
      } else {
        setMessage("Check your email to confirm your account, then log in.");
        setMode("login");
      }
    }
    setIsLoading(false);
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-300 font-sans flex flex-col items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-3 mb-8 justify-center">
          <Shield className="w-7 h-7 text-emerald-500" />
          <h1 className="font-mono text-xl font-medium text-zinc-100 tracking-tight">
            Sentinel Lite
          </h1>
          <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider bg-zinc-800 text-zinc-400 border border-zinc-700">
            v2.1.0-RT
          </span>
        </div>

        <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-6">
          <h2 className="text-xs font-mono uppercase tracking-widest text-zinc-400 mb-6">
            {mode === "login" ? "Operator Login" : "Request Access"}
          </h2>

          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full px-3 py-2.5 bg-zinc-950 border border-zinc-800 rounded font-mono text-sm text-zinc-200 focus:outline-none focus:border-emerald-500/50"
                placeholder="operator@domain.com"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full px-3 py-2.5 bg-zinc-950 border border-zinc-800 rounded font-mono text-sm text-zinc-200 focus:outline-none focus:border-emerald-500/50"
                placeholder="••••••••"
              />
            </div>

            {error && (
              <div className="flex items-start gap-2 p-3 rounded border border-red-500/20 bg-red-500/10 text-red-400 text-xs font-mono">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                {error}
              </div>
            )}

            {message && (
              <div className="p-3 rounded border border-emerald-500/20 bg-emerald-500/10 text-emerald-400 text-xs font-mono">
                {message}
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading}
              className="flex items-center justify-center gap-2 px-4 py-2.5 bg-emerald-500 hover:bg-emerald-400 disabled:bg-zinc-800 disabled:text-zinc-500 text-zinc-950 font-mono text-xs uppercase tracking-wider font-semibold rounded transition-colors"
            >
              {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
              {mode === "login" ? "Login" : "Sign Up"}
            </button>
          </form>

          <div className="mt-4 pt-4 border-t border-zinc-800 text-center">
            <button
              onClick={() => {
                setMode((m) => (m === "login" ? "signup" : "login"));
                setError(null);
                setMessage(null);
              }}
              className="text-[11px] font-mono text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              {mode === "login"
                ? "Don't have access? Sign up"
                : "Already have an account? Login"}
            </button>
          </div>
        </div>

        <p className="text-center text-[10px] font-mono text-zinc-600 mt-4">
          Secured by Supabase Auth · Sentinel Lite
        </p>
      </div>
    </div>
  );
}
