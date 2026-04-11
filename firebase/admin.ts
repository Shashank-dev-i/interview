import { createPrivateKey } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

import { cert, getApps, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";

/**
 * Re-encode PEM so OpenSSL / google-auth can sign JWTs.
 * Fixes many Windows/.env mangling cases and surfaces a clear error if the key is garbage.
 */
function coercePrivateKeyPem(raw: string): string {
  let pem = raw
    .trim()
    .replace(/^\uFEFF/, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");

  if (
    (pem.startsWith('"') && pem.endsWith('"')) ||
    (pem.startsWith("'") && pem.endsWith("'"))
  ) {
    pem = pem.slice(1, -1).replace(/\\n/g, "\n");
  } else if (!pem.includes("BEGIN ") && pem.includes("\\n")) {
    pem = pem.replace(/\\n/g, "\n");
  }

  try {
    const key = createPrivateKey({ key: pem, format: "pem" });
    return key.export({ format: "pem", type: "pkcs8" }) as string;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(
      `Firebase Admin private key is invalid (Node crypto: ${msg}). ` +
        "Fix: set FIREBASE_SERVICE_ACCOUNT_PATH to the JSON file from Firebase Console " +
        "(Project settings → Service accounts → Generate new private key), " +
        "or paste the full JSON into FIREBASE_SERVICE_ACCOUNT_JSON. " +
        "Avoid FIREBASE_PRIVATE_KEY on Windows unless you are sure the PEM is perfect.",
    );
  }
}

/** PEM from .env only (before crypto coercion). */
function normalizePrivateKeyFromEnv(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  return coercePrivateKeyPem(raw);
}

type ServiceAccountJson = {
  project_id: string;
  client_email: string;
  private_key: string;
};

function certFromServiceAccount(sa: ServiceAccountJson) {
  const privateKey = coercePrivateKeyPem(sa.private_key);
  return cert({
    projectId: sa.project_id,
    clientEmail: sa.client_email,
    privateKey,
  });
}

function resolveCredentialFilePath(raw: string): string {
  const trimmed = raw.trim().replace(/^["']|["']$/g, "");
  if (isAbsolute(trimmed)) return resolve(trimmed);
  return resolve(process.cwd(), trimmed);
}

/**
 * Use ONLY FIREBASE_SERVICE_ACCOUNT_PATH (not GOOGLE_APPLICATION_CREDENTIALS) so a broken
 * system-wide GAC on Windows does not override your .env.local.
 */
function initFromServiceAccountFile(filePath: string) {
  const abs = resolveCredentialFilePath(filePath);
  if (!existsSync(abs)) {
    throw new Error(
      `FIREBASE_SERVICE_ACCOUNT_PATH file not found: ${abs}\n` +
        "(path is resolved from the project directory where you run next dev)",
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
    const filePath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH?.trim();

    if (filePath) {
      initFromServiceAccountFile(filePath);
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
        const privateKey = normalizePrivateKeyFromEnv(
          process.env.FIREBASE_PRIVATE_KEY,
        );
        const projectId = process.env.FIREBASE_PROJECT_ID?.trim();
        const clientEmail = process.env.FIREBASE_CLIENT_EMAIL?.trim();

        if (
          !privateKey ||
          !privateKey.includes("BEGIN PRIVATE KEY") ||
          !projectId ||
          !clientEmail
        ) {
          throw new Error(
            "Firebase Admin: set FIREBASE_SERVICE_ACCOUNT_PATH=./your-key.json in .env.local\n" +
              "(download JSON from Firebase → Project settings → Service accounts).\n" +
              "Do not rely on GOOGLE_APPLICATION_CREDENTIALS for this app — a wrong system env breaks sign-in.\n" +
              "Alternative: FIREBASE_SERVICE_ACCOUNT_JSON={...one line...}",
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
