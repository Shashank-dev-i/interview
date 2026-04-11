import {
  applicationDefault,
  cert,
  getApps,
  initializeApp,
} from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";

/** PEM from .env: fix Windows quoting, escaped newlines, and stray BOM. */
function normalizePrivateKey(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  let key = raw.trim().replace(/^\uFEFF/, "");
  if (
    (key.startsWith('"') && key.endsWith('"')) ||
    (key.startsWith("'") && key.endsWith("'"))
  ) {
    key = key.slice(1, -1);
  }
  return key.replace(/\\n/g, "\n").trim();
}

type ServiceAccountJson = {
  project_id: string;
  client_email: string;
  private_key: string;
};

function certFromServiceAccount(sa: ServiceAccountJson) {
  return cert({
    projectId: sa.project_id,
    clientEmail: sa.client_email,
    privateKey: sa.private_key,
  });
}

function initFirebaseAdmin() {
  const apps = getApps();

  if (!apps.length) {
    const gac = process.env.GOOGLE_APPLICATION_CREDENTIALS?.trim();
    if (gac) {
      initializeApp({ credential: applicationDefault() });
    } else {
      const rawJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON?.trim();
      if (rawJson) {
        let parsed: ServiceAccountJson;
        try {
          parsed = JSON.parse(rawJson) as ServiceAccountJson;
        } catch {
          throw new Error(
            "FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON. Paste the full service account JSON on one line.",
          );
        }
        if (!parsed.private_key || !parsed.client_email || !parsed.project_id) {
          throw new Error(
            "FIREBASE_SERVICE_ACCOUNT_JSON must include project_id, client_email, and private_key.",
          );
        }
        initializeApp({ credential: certFromServiceAccount(parsed) });
      } else {
        const privateKey = normalizePrivateKey(process.env.FIREBASE_PRIVATE_KEY);
        const projectId = process.env.FIREBASE_PROJECT_ID?.trim();
        const clientEmail = process.env.FIREBASE_CLIENT_EMAIL?.trim();

        if (
          !privateKey ||
          !privateKey.includes("BEGIN PRIVATE KEY") ||
          !projectId ||
          !clientEmail
        ) {
          throw new Error(
            "Firebase Admin: use one of these in .env.local:\n" +
              "1) GOOGLE_APPLICATION_CREDENTIALS=C:/full/path/to/serviceAccount.json (recommended on Windows)\n" +
              "2) FIREBASE_SERVICE_ACCOUNT_JSON={...full JSON on one line...}\n" +
              "3) FIREBASE_PROJECT_ID + FIREBASE_CLIENT_EMAIL + FIREBASE_PRIVATE_KEY (one line, \\n for newlines)",
          );
        }

        initializeApp({
          credential: cert({
            projectId,
            clientEmail,
            privateKey,
          }),
        });
      }
    }
  }

  return {
    auth: getAuth(),
    db: getFirestore(),
  };
}

export const { auth, db } = initFirebaseAdmin();
