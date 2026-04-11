/**
 * If serviceAccount.json was saved as .env-style lines, rewrite it as real
 * Firebase service account JSON. Safe to re-run; skips if file already is JSON.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const path = resolve(process.cwd(), "serviceAccount.json");
const raw = readFileSync(path, "utf8").trim();
if (raw.startsWith("{")) {
  console.log("serviceAccount.json already looks like JSON; no change.");
  process.exit(0);
}

const vars = {};
for (const line of raw.split(/\r?\n/)) {
  if (!line.trim() || line.startsWith("#")) continue;
  const i = line.indexOf("=");
  if (i === -1) continue;
  const k = line.slice(0, i).trim();
  let v = line.slice(i + 1).trim();
  if (v.endsWith(",")) v = v.slice(0, -1).trim();
  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    v = v.slice(1, -1);
  }
  v = v.replace(/\\n/g, "\n");
  vars[k] = v;
}

const doc = {
  type: "service_account",
  project_id: vars.FIREBASE_PROJECT_ID,
  private_key_id: "",
  private_key: vars.FIREBASE_PRIVATE_KEY,
  client_email: vars.FIREBASE_CLIENT_EMAIL,
  client_id: "",
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
};

if (!doc.project_id || !doc.private_key || !doc.client_email) {
  console.error("Could not parse FIREBASE_* fields from serviceAccount.json");
  process.exit(1);
}

writeFileSync(path, JSON.stringify(doc, null, 2));
console.log("Wrote valid serviceAccount.json");
