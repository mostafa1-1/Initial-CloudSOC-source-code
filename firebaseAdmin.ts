import fs from 'node:fs';
import path from 'node:path';
import { cert, getApps, initializeApp, type ServiceAccount } from 'firebase-admin/app';
import { getAuth, type Auth } from 'firebase-admin/auth';

const ADMIN_APP_NAME = 'cloudsoc-firebase-admin';
let cachedAuth: Auth | null | undefined;

/**
 * Lazily initialize Firebase Admin. The private service-account JSON must never
 * be placed in src/, committed to Git, or exposed to the browser.
 */
export function getFirebaseAdminAuth(): Auth | null {
  if (cachedAuth !== undefined) return cachedAuth;

  const inlineJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON?.trim();
  const configuredPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH?.trim();
  if (!inlineJson && !configuredPath) {
    cachedAuth = null;
    return cachedAuth;
  }

  let serviceAccount: ServiceAccount;
  try {
    const raw = inlineJson
      ? inlineJson
      : fs.readFileSync(path.resolve(process.cwd(), configuredPath!), 'utf8');
    serviceAccount = JSON.parse(raw) as ServiceAccount;
  } catch {
    throw new Error('Firebase Admin credentials could not be read. Check FIREBASE_SERVICE_ACCOUNT_PATH or FIREBASE_SERVICE_ACCOUNT_JSON.');
  }

  const projectId = process.env.FIREBASE_PROJECT_ID || serviceAccount.projectId;
  const existing = getApps().find((app) => app.name === ADMIN_APP_NAME);
  const app = existing || initializeApp(
    { credential: cert(serviceAccount), ...(projectId ? { projectId } : {}) },
    ADMIN_APP_NAME,
  );
  cachedAuth = getAuth(app);
  return cachedAuth;
}
