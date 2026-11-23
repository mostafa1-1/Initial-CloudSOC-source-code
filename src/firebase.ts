import { getApp, getApps, initializeApp } from 'firebase/app';
import { getAuth } from 'firebase/auth';

const apiKey = import.meta.env.VITE_FIREBASE_API_KEY || '';
const authDomain = import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || '';
const projectId = import.meta.env.VITE_FIREBASE_PROJECT_ID || '';
const appId = import.meta.env.VITE_FIREBASE_APP_ID || '';
const storageBucket = import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || undefined;
const messagingSenderId = import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || undefined;

export const isFirebaseConfigured = Boolean(apiKey && authDomain && projectId && appId);

const firebaseConfig = {
  apiKey,
  authDomain,
  projectId,
  appId,
  ...(storageBucket ? { storageBucket } : {}),
  ...(messagingSenderId ? { messagingSenderId } : {}),
};

export const firebaseApp = isFirebaseConfigured
  ? getApps().length > 0
    ? getApp()
    : initializeApp(firebaseConfig)
  : null;

export const firebaseAuth = firebaseApp ? getAuth(firebaseApp) : null;
