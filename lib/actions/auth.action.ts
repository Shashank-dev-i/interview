"use server";

import { auth, db } from "@/firebase/admin";
import { cookies } from "next/headers";


const SESSION_DURATION = 60 * 60 * 24 * 7;

function adminErrorMessage(error: unknown): string {
  const e = error as {
    code?: string;
    errorInfo?: { code?: string; message?: string };
  };
  const code = e?.code ?? e?.errorInfo?.code ?? "";

  switch (code) {
    case "auth/user-not-found":
      return "No account found for this email. Sign up first.";
    case "auth/invalid-email":
      return "Invalid email address.";
    case "auth/invalid-id-token":
    case "auth/argument-error":
      return "Could not verify your sign-in. Try again or use a different browser.";
    case "auth/id-token-expired":
      return "Sign-in expired. Please try signing in again.";
    default:
      if (process.env.NODE_ENV === "development" && e?.errorInfo?.message) {
        return e.errorInfo.message;
      }
      return "Failed to log into account. Please try again.";
  }
}

/** Must stay non-exported so signIn sets cookies in one server-action boundary (Next.js). */
async function commitSessionCookie(idToken: string) {
  const cookieStore = await cookies();
  const sessionCookie = await auth.createSessionCookie(idToken, {
    expiresIn: SESSION_DURATION * 1000,
  });
  cookieStore.set("session", sessionCookie, {
    maxAge: SESSION_DURATION,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    path: "/",
    sameSite: "lax",
  });
}

export async function signUp(params: SignUpParams) {
  const { uid, name, email } = params;

  try {
    const userRecord = await db.collection("users").doc(uid).get();
    if (userRecord.exists)
      return {
        success: false,
        message: "User already exists. Please sign in.",
      };

    await db.collection("users").doc(uid).set({
      name,
      email,
    });

    return {
      success: true,
      message: "Account created successfully. Please sign in.",
    };
  } catch (error: any) {
    console.error("Error creating user:", error);

    if (error.code === "auth/email-already-exists") {
      return {
        success: false,
        message: "This email is already in use",
      };
    }

    return {
      success: false,
      message: "Failed to create account. Please try again.",
    };
  }
}

export async function signIn(
  params: SignInParams,
): Promise<{ success: true } | { success: false; message: string }> {
  const { email, idToken } = params;
  const normalizedEmail = email.trim().toLowerCase();

  try {
    const userRecord = await auth.getUserByEmail(normalizedEmail);
    const userDoc = db.collection("users").doc(userRecord.uid);
    const snap = await userDoc.get();
    if (!snap.exists) {
      await userDoc.set({
        name:
          userRecord.displayName ||
          userRecord.email?.split("@")[0] ||
          "User",
        email: userRecord.email ?? email,
      });
    }

    await commitSessionCookie(idToken);
    return { success: true };
  } catch (error) {
    console.error("signIn server action:", error);
    return {
      success: false,
      message: adminErrorMessage(error),
    };
  }
}

export async function signOut() {
  const cookieStore = await cookies();

  cookieStore.delete("session");
}

export async function getCurrentUser(): Promise<User | null> {
  const cookieStore = await cookies();

  const sessionCookie = cookieStore.get("session")?.value;
  if (!sessionCookie) return null;

  try {
    const decodedClaims = await auth.verifySessionCookie(sessionCookie, true);

    const userRecord = await db
      .collection("users")
      .doc(decodedClaims.uid)
      .get();
    if (!userRecord.exists) return null;

    return {
      ...userRecord.data(),
      id: userRecord.id,
    } as User;
  } catch {
    // Invalid/expired/wrong-project cookie — cannot delete here (RSC/layout); use signOut or clear site cookies
    return null;
  }
}

export async function isAuthenticated() {
  const user = await getCurrentUser();
  return !!user;
}
