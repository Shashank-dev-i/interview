import { getApp, getApps, initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

/** Same Firebase project as Admin (`interviewprepration-b1339`). Env overrides when set. */
const defaultWebConfig = {
  apiKey: "AIzaSyDhlr6fsYWJavos1Qan2MmPaZMbm212r7Y",
  authDomain: "interviewprepration-b1339.firebaseapp.com",
  projectId: "interviewprepration-b1339",
  storageBucket: "interviewprepration-b1339.firebasestorage.app",
  messagingSenderId: "438906680216",
  appId: "1:438906680216:web:9e7450d0789f530dd7b1ed",
  measurementId: "G-7GPNN6V05L",
} as const;

function envOr(key: keyof typeof defaultWebConfig, envName: string): string {
  const raw = process.env[envName]?.trim();
  if (raw) return raw;
  return defaultWebConfig[key];
}

const firebaseConfig = {
  apiKey: envOr("apiKey", "NEXT_PUBLIC_FIREBASE_API_KEY"),
  authDomain: envOr("authDomain", "NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN"),
  projectId: envOr("projectId", "NEXT_PUBLIC_FIREBASE_PROJECT_ID"),
  storageBucket: envOr("storageBucket", "NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET"),
  messagingSenderId: envOr(
    "messagingSenderId",
    "NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID",
  ),
  appId: envOr("appId", "NEXT_PUBLIC_FIREBASE_APP_ID"),
  measurementId:
    process.env.NEXT_PUBLIC_FIREBASE_MEASUREMENT_ID?.trim() ||
    defaultWebConfig.measurementId,
};

const app = !getApps().length ? initializeApp(firebaseConfig) : getApp();

export const auth = getAuth(app);
export const db = getFirestore(app);
