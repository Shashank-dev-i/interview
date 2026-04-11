import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { cert, getApps, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";

/** PEM from .env: Windows quoting, escaped newlines, BOM, CRLF. */
function normalizePrivateKey(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  let key = raw.trim().replace(/^\uFEFF/, "");
  if (
    (key.startsWith('"') && key.endsWith('"')) ||
    (key.startsWith("'") && key.endsWith("'"))
  ) {
    key = key.slice(1, -1);
  }
  return key
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(/\\n/g, "\n")
    .trim();
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

function resolveJsonPath(raw: string): string {
  const trimmed = raw.trim().replace(/^["']|["']$/g, "");
  return resolve(trimmed);
}

/** Prefer this on Windows: JSON file keeps private_key newlines intact. */
function initFromServiceAccountFile(filePath: string) {
  const abs = resolveJsonPath(filePath);
  if (!existsSync(abs)) {
    throw new Error(
      `Firebase Admin: service account file not found: ${abs}\n` +
        "Download a new key from Firebase Console → Project settings → Service accounts.",
    );
  }
  const parsed = JSON.parse(readFileSync(abs, "utf8")) as ServiceAccountJson;
  if (!parsed.private_key || !parsed.client_email || !parsed.project_id) {
    throw new Error(
      "Service account JSON must include project_id, client_email, and private_key.",
    );
  }
  initializeApp({ credential: certFromServiceAccount(parsed) });
}

function initFirebaseAdmin() {
  const apps = getApps();

  if (!apps.length) {
    const pathEnv =
      process.env.FIREBASE_SERVICE_ACCOUNT_PATH?.trim() ||
      process.env.GOOGLE_APPLICATION_CREDENTIALS?.trim();

    if (pathEnv) {
      initFromServiceAccountFile(pathEnv);
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
            "Firebase Admin (fix DECODER error on Windows):\n" +
              "1) Download service account JSON from Firebase Console → Project settings → Service accounts.\n" +
              "2) Save it as e.g. prep/serviceAccount.json (do not commit).\n" +
              "3) In .env.local add ONE of:\n" +
              "   FIREBASE_SERVICE_ACCOUNT_PATH=./serviceAccount.json\n" +
              "   or GOOGLE_APPLICATION_CREDENTIALS=C:/full/path/to/key.json\n" +
              "4) Remove broken FIREBASE_PRIVATE_KEY lines.\n" +
              "Optional: FIREBASE_SERVICE_ACCOUNT_JSON={...single-line JSON...}",
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
