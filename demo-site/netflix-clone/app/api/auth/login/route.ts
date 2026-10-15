// Demo auth endpoint for the Netflix-clone target site. It validates against a
// hard-coded demo password, so the credential-abuse (R2L) attack hits a real
// login surface that returns 401 on wrong guesses — making the walkthrough feel
// real. This is a throwaway lab login, not a secure authentication system.

const DEMO_USER = "admin";
const DEMO_PASS = "netflix123";

export async function POST(request: Request) {
  let body: { username?: string; password?: string } = {};
  try {
    body = await request.json();
  } catch {
    // Non-JSON body (e.g. a scanner/brute-forcer) — treat as a failed attempt.
  }

  if (body.username === DEMO_USER && body.password === DEMO_PASS) {
    return Response.json({ ok: true, token: "demo-session" });
  }
  return Response.json({ ok: false, error: "Invalid credentials" }, { status: 401 });
}
