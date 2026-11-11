// grimaldello adapter for @simplewebauthn/server.
// Reads cases (JSON lines) on stdin, writes one verdict per line on stdout.

import { createInterface } from "node:readline";
import { readFileSync } from "node:fs";
import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";

if (process.argv.includes("--info")) {
  const pkg = JSON.parse(readFileSync(new URL("./node_modules/@simplewebauthn/server/package.json", import.meta.url)));
  console.log(JSON.stringify({ library: "@simplewebauthn/server", version: pkg.version, language: "TypeScript" }));
  process.exit(0);
}

async function register(c) {
  const r = await verifyRegistrationResponse({
    response: c.registration.response,
    expectedChallenge: c.registration.challenge,
    expectedOrigin: c.rp.origin,
    expectedRPID: c.rp.id,
    requireUserVerification: c.requireUserVerification,
    supportedAlgorithmIDs: c.algorithms,
  });
  if (!r.verified) throw new Error("verified: false");
  return r.registrationInfo.credential;
}

async function verify(c) {
  if (c.ceremony === "registration") {
    await register(c);
    return;
  }
  let credential;
  try {
    credential = await register(c);
  } catch (e) {
    throw new Error(`setup: registration failed: ${e.message}`);
  }
  const a = c.authentication;
  // What an application does: look the credential up by the id in the response.
  if (a.response.id !== credential.id) throw new Error("unknown credential");
  const r = await verifyAuthenticationResponse({
    response: a.response,
    expectedChallenge: a.challenge,
    expectedOrigin: c.rp.origin,
    expectedRPID: c.rp.id,
    credential: { ...credential, counter: a.storedSignCount },
    requireUserVerification: c.requireUserVerification,
  });
  if (!r.verified) throw new Error("verified: false");
}

for await (const line of createInterface({ input: process.stdin })) {
  if (!line.trim()) continue;
  const c = JSON.parse(line);
  let out;
  try {
    await verify(c);
    out = { id: c.id, verdict: "accept" };
  } catch (e) {
    out = { id: c.id, verdict: "reject", error: String(e?.message ?? e) };
  }
  console.log(JSON.stringify(out));
}
