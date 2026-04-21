import { createPrivateKey } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

import { cert, getApps, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";

/** Newlines only — keys straight from Firebase JSON files are already valid PEM. */
function normalizePrivateKeyFromJsonField(raw: string): string {
  return raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

/**
 * PEM pasted into .env is often corrupted on Windows. Re-encode when possible.
 */
function coercePrivateKeyPemFromEnv(raw: string): string {
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
      `FIREBASE_PRIVATE_KEY in .env.local is broken (${msg}).\n\n` +
        "Do this instead:\n" +
        "1) Delete FIREBASE_PRIVATE_KEY, FIREBASE_CLIENT_EMAIL, and FIREBASE_PROJECT_ID from .env.local.\n" +
        "2) Firebase Console → Project settings → Service accounts → Generate new private key.\n" +
        "3) Save as serviceAccount.json next to package.json, then add:\n" +
        "   FIREBASE_SERVICE_ACCOUNT_PATH=./serviceAccount.json\n" +
        "   OR set FIREBASE_SERVICE_ACCOUNT_BASE64=<base64 of the entire JSON file> (PowerShell: [Convert]::ToBase64String([IO.File]::ReadAllBytes('path\\to\\key.json')))\n" +
        "   OR FIREBASE_SERVICE_ACCOUNT_JSON={...single-line JSON...}\n\n" +
        "Restart npm run dev after saving .env.local.",
    );
  }
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
    privateKey: normalizePrivateKeyFromJsonField(sa.private_key),
  });
}

function parseServiceAccountJson(jsonText: string): ServiceAccountJson {
  const parsed = JSON.parse(jsonText) as ServiceAccountJson;
  if (!parsed.private_key || !parsed.client_email || !parsed.project_id) {
    throw new Error(
      "Service account JSON must include project_id, client_email, and private_key.",
    );
  }
  return parsed;
}

function resolveCredentialFilePath(raw: string): string {
  const trimmed = raw.trim().replace(/^["']|["']$/g, "");
  if (isAbsolute(trimmed)) return resolve(trimmed);
  return resolve(process.cwd(), trimmed);
}

function initFromServiceAccountFile(filePath: string) {
  const abs = resolveCredentialFilePath(filePath);
  if (!existsSync(abs)) {
    throw new Error(
      `FIREBASE_SERVICE_ACCOUNT_PATH file not found: ${abs}\n` +
        "(path is relative to the folder where you run `npm run dev`)",
    );
  }
  const parsed = parseServiceAccountJson(readFileSync(abs, "utf8"));
  initializeApp({ credential: certFromServiceAccount(parsed) });
}

function initFirebaseAdmin() {
  const apps = getApps();

  if (!apps.length) {
    const filePath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH?.trim();
    const base64 = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64?.trim();
    const rawJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON?.trim();
    const rawPem = process.env.FIREBASE_PRIVATE_KEY;
    const projectId = process.env.FIREBASE_PROJECT_ID?.trim();
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL?.trim();

    if (filePath) {
      const abs = resolveCredentialFilePath(filePath);
      if (existsSync(abs)) {
        initFromServiceAccountFile(filePath);
      } else if (!base64 && !rawJson && (!rawPem?.trim() || !projectId || !clientEmail)) {
        throw new Error(
          `FIREBASE_SERVICE_ACCOUNT_PATH file not found: ${abs}\n` +
            "Set one of these env vars in your deploy environment:\n" +
            "  FIREBASE_SERVICE_ACCOUNT_BASE64=<base64 of full JSON>\n" +
            "  FIREBASE_SERVICE_ACCOUNT_JSON={...}\n" +
            "  OR FIREBASE_PRIVATE_KEY + FIREBASE_CLIENT_EMAIL + FIREBASE_PROJECT_ID",
        );
      }
    } else if (base64) {
      let jsonText: string;
      try {
        jsonText = Buffer.from(base64, "base64").toString("utf8");
      } catch {
        throw new Error(
          "FIREBASE_SERVICE_ACCOUNT_BASE64 is not valid base64.",
        );
      }
      const parsed = parseServiceAccountJson(jsonText);
      initializeApp({ credential: certFromServiceAccount(parsed) });
    } else if (rawJson) {
      let parsed: ServiceAccountJson;
      try {
        parsed = parseServiceAccountJson(rawJson);
      } catch (e) {
        if (e instanceof SyntaxError) {
          throw new Error(
            "FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON. Use one line, or use FIREBASE_SERVICE_ACCOUNT_PATH / BASE64 instead.",
          );
        }
        throw e;
      }
      initializeApp({ credential: certFromServiceAccount(parsed) });
    } else {
      if (!rawPem?.trim() || !projectId || !clientEmail) {
        throw new Error(
          "Firebase Admin: add to .env.local one of:\n" +
            "  FIREBASE_SERVICE_ACCOUNT_PATH=./serviceAccount.json\n" +
            "  FIREBASE_SERVICE_ACCOUNT_BASE64=<base64 of full JSON>\n" +
            "  FIREBASE_SERVICE_ACCOUNT_JSON={...}\n" +
            "Download JSON from Firebase → Project settings → Service accounts.",
        );
      }

      const privateKey = coercePrivateKeyPemFromEnv(rawPem);

      if (!privateKey.includes("BEGIN PRIVATE KEY")) {
        throw new Error(
          "FIREBASE_PRIVATE_KEY must contain BEGIN PRIVATE KEY. Prefer FIREBASE_SERVICE_ACCOUNT_PATH with the JSON file instead.",
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

  return {
    auth: getAuth(),
    db: getFirestore(),
  };
}

export const { auth, db } = initFirebaseAdmin();
