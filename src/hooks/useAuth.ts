import { useEffect, useState } from 'react';
import { onAuthStateChanged, User } from 'firebase/auth';
import { doc, getDoc } from 'firebase/firestore';
import { auth, db } from '../firebase';

export type AuthState = 'loading' | 'unauthenticated' | 'unauthorized' | 'authorized';

export interface AuthContext {
  user: User | null;
  authState: AuthState;
}

export function useAuth(): AuthContext {
  const [user, setUser] = useState<User | null>(null);
  const [authState, setAuthState] = useState<AuthState>('loading');

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (!firebaseUser) {
        setUser(null);
        setAuthState('unauthenticated');
        return;
      }
      setUser(firebaseUser);
      if (!firebaseUser.email) {
        setAuthState('unauthorized');
        return;
      }
      try {
        const whitelistRef = doc(db, 'whitelist', firebaseUser.email);
        const whitelistSnap = await getDoc(whitelistRef);
        setAuthState(whitelistSnap.exists() ? 'authorized' : 'unauthorized');
      } catch {
        setAuthState('unauthorized');
      }
    });
    return unsubscribe;
  }, []);

  return { user, authState };
}
