import React, { useState } from 'react';
import { signInWithPopup, signOut } from 'firebase/auth';
import { Shield, Loader2, LogIn, AlertTriangle, LogOut } from 'lucide-react';
import { auth, googleProvider } from '../firebase';
import { useAuth } from '../hooks/useAuth';

interface AuthGateProps {
  children: React.ReactNode;
}

export function AuthGate({ children }: AuthGateProps) {
  const { user, authState } = useAuth();
  const [loginError, setLoginError] = useState<string | null>(null);
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  const handleLogin = async () => {
    setIsLoggingIn(true);
    setLoginError(null);
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (error: any) {
      setLoginError('Sign-in failed. Please try again.');
      console.error('[Sentinel] Auth error:', error?.code);
    } finally {
      setIsLoggingIn(false);
    }
  };

  if (authState === 'loading') {
    return (
      <div className="min-h-screen bg-zinc-950 flex flex-col items-center justify-center gap-4">
        <Shield className="w-10 h-10 text-emerald-500" />
        <Loader2 className="w-6 h-6 text-emerald-500/60 animate-spin" />
      </div>
    );
  }

  if (authState === 'unauthenticated') {
    return (
      <div className="min-h-screen bg-zinc-950 text-zinc-300 flex items-center justify-center px-4">
        <div className="w-full max-w-sm flex flex-col items-center gap-6">
          <div className="flex flex-col items-center gap-3">
            <Shield className="w-14 h-14 text-emerald-500" />
            <h1 className="font-mono text-xl font-semibold text-zinc-100 tracking-tight">CompTIA Sentinel</h1>
            <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-widest text-zinc-500">
              <span>SY0-701</span><span className="text-zinc-700">·</span>
              <span>CV0-003</span><span className="text-zinc-700">·</span>
              <span>Authorized Access Only</span>
            </div>
          </div>
          <div className="w-full p-6 rounded-lg border border-zinc-800 bg-zinc-900/50 flex flex-col gap-4">
            <p className="text-xs text-zinc-400 text-center font-mono">
              Sign in with your authorized Google account to continue.
            </p>
            <button
              onClick={handleLogin}
              disabled={isLoggingIn}
              className="flex items-center justify-center gap-2 w-full px-4 py-3 bg-emerald-500 hover:bg-emerald-400 disabled:bg-zinc-700 disabled:text-zinc-500 text-zinc-950 font-mono text-sm font-semibold rounded transition-colors"
            >
              {isLoggingIn ? <Loader2 className="w-4 h-4 animate-spin" /> : <LogIn className="w-4 h-4" />}
              {isLoggingIn ? 'Signing in...' : 'Sign in with Google'}
            </button>
            {loginError && <p className="text-red-400 text-xs font-mono text-center">{loginError}</p>}
          </div>
          <p className="text-[10px] text-zinc-600 font-mono text-center">
            Access requires whitelist authorization. Contact your administrator.
          </p>
        </div>
      </div>
    );
  }

  if (authState === 'unauthorized') {
    return (
      <div className="min-h-screen bg-zinc-950 text-zinc-300 flex items-center justify-center px-4">
        <div className="w-full max-w-sm flex flex-col items-center gap-6">
          <AlertTriangle className="w-12 h-12 text-red-500" />
          <div className="text-center">
            <h2 className="font-mono text-lg font-semibold text-zinc-100 mb-1">Access Denied</h2>
            <p className="text-sm text-zinc-400 font-mono">{user?.email}</p>
            <p className="text-xs text-zinc-600 font-mono mt-2">This account is not authorized to access Sentinel.</p>
          </div>
          <button
            onClick={() => signOut(auth)}
            className="flex items-center gap-2 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 font-mono text-xs rounded border border-zinc-700 transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />Sign out
          </button>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}

export { signOut, auth };
