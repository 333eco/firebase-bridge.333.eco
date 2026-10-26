// The bridge's guarantees, each proved by BREAKING it: every refusal below is a known failure the bridge must catch.
// A suite of passes alone would be an untested claim; the controls are the point.
import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, generateKeyPair, exportJWK, createLocalJWKSet, UnsecuredJWT } from "jose";
import { createBridge, BridgeError } from "../dist/index.js";

const ISS = "https://login.333.eco";
const CLIENT = "origin-333-eco";
const { privateKey, publicKey } = await generateKeyPair("ES256");
const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256" };
const keys = createLocalJWKSet({ keys: [jwk] });
const other = await generateKeyPair("ES256"); // a key the issuer never published

const minted = [];
const auth = { createCustomToken: async (uid, claims) => { minted.push({ uid, claims }); return `custom:${uid}`; } };
const bridge = (o = {}) => createBridge({ issuer: ISS, clientId: CLIENT, auth, keys, ...o });

async function idToken({ key = privateKey, kid = "k1", iss = ISS, aud = CLIENT, sub = "pw_7f3a91c2", nonce = "n-1",
                         amr = ["hwk", "user"], noAmr = false, exp = "5m", iat, auth_time, extra = {} } = {}) {
    let j = new SignJWT({ nonce, ...(noAmr ? {} : { amr }), ...(auth_time ? { auth_time } : {}), ...extra })
        .setProtectedHeader({ alg: "ES256", kid }).setIssuer(iss).setAudience(aud).setSubject(sub).setExpirationTime(exp);
    j = iat ? j.setIssuedAt(iat) : j.setIssuedAt();
    return j.sign(key);
}
async function refuses(p, code) {
    await assert.rejects(p, (e) => e instanceof BridgeError && e.code === code, `expected ${code}`);
}

test("a valid passkey token mints a custom token with amr copied", async () => {
    const r = await bridge().exchange(await idToken(), { nonce: "n-1" });
    assert.equal(r.uid, "hb:pw_7f3a91c2");
    assert.equal(r.passkey, true);
    assert.deepEqual(minted.at(-1).claims, { hb_amr: ["hwk", "user"], hb_passkey: true });
});

test("an SMS session passes by default but is marked passkey:false", async () => {
    const r = await bridge().exchange(await idToken({ amr: ["sms"] }), { nonce: "n-1" });
    assert.equal(r.passkey, false);
});

test("CONTROL: requirePasskey refuses an SMS session", async () => {
    await refuses(bridge({ requirePasskey: true }).exchange(await idToken({ amr: ["sms"] }), { nonce: "n-1" }), "passkey_required");
});
test("CONTROL: requirePasskey refuses a token with no amr at all", async () => {
    await refuses(bridge({ requirePasskey: true }).exchange(await idToken({ noAmr: true }), { nonce: "n-1" }), "passkey_required");
});
test("CONTROL: a token signed by an unpublished key is refused", async () => {
    await refuses(bridge().exchange(await idToken({ key: other.privateKey }), { nonce: "n-1" }), "invalid_token");
});
test("CONTROL: a tampered payload is refused", async () => {
    const t = await idToken();
    const [h, p, s] = t.split(".");
    const forged = JSON.parse(Buffer.from(p, "base64url").toString());
    forged.sub = "pw_someone_else";
    await refuses(bridge().exchange([h, Buffer.from(JSON.stringify(forged)).toString("base64url"), s].join("."), { nonce: "n-1" }), "invalid_token");
});
test("CONTROL: alg none is refused (algorithm confusion)", async () => {
    const t = new UnsecuredJWT({ nonce: "n-1", amr: ["hwk"] }).setIssuer(ISS).setAudience(CLIENT).setSubject("x").setIssuedAt().setExpirationTime("5m").encode();
    await refuses(bridge().exchange(t, { nonce: "n-1" }), "invalid_token");
});
test("CONTROL: an HS256 token is refused even if it claims the right kid", async () => {
    const t = await new SignJWT({ nonce: "n-1", amr: ["hwk"] }).setProtectedHeader({ alg: "HS256", kid: "k1" })
        .setIssuer(ISS).setAudience(CLIENT).setSubject("x").setIssuedAt().setExpirationTime("5m").sign(new TextEncoder().encode("secret-secret-secret-secret-1234"));
    await refuses(bridge().exchange(t, { nonce: "n-1" }), "invalid_token");
});
test("CONTROL: a token for another app (aud) is refused", async () => {
    await refuses(bridge().exchange(await idToken({ aud: "pixel-wild" }), { nonce: "n-1" }), "invalid_token");
});
test("CONTROL: a token from another issuer is refused", async () => {
    await refuses(bridge().exchange(await idToken({ iss: "https://evil.example" }), { nonce: "n-1" }), "invalid_token");
});
test("CONTROL: an expired token is refused", async () => {
    const past = Math.floor(Date.now() / 1000) - 3600;
    await refuses(bridge().exchange(await idToken({ iat: past - 300, exp: past }), { nonce: "n-1" }), "invalid_token");
});
test("CONTROL: a wrong nonce (a replay into another session) is refused", async () => {
    await refuses(bridge().exchange(await idToken({ nonce: "n-1" }), { nonce: "n-2" }), "wrong_nonce");
});
test("CONTROL: a missing nonce check is refused", async () => {
    await refuses(bridge().exchange(await idToken(), {}), "wrong_nonce");
});
test("CONTROL: multiple audiences without azp = this client are refused", async () => {
    await refuses(bridge().exchange(await idToken({ aud: [CLIENT, "other"] }), { nonce: "n-1" }), "invalid_token");
    const ok = await bridge().exchange(await idToken({ aud: [CLIENT, "other"], extra: { azp: CLIENT } }), { nonce: "n-1" });
    assert.equal(ok.uid, "hb:pw_7f3a91c2");
});
test("CONTROL: maxAgeSeconds refuses an old log-in", async () => {
    const old = Math.floor(Date.now() / 1000) - 7200;
    await refuses(bridge({ maxAgeSeconds: 600 }).exchange(await idToken({ auth_time: old }), { nonce: "n-1" }), "too_old");
    const fresh = Math.floor(Date.now() / 1000) - 10;
    assert.equal((await bridge({ maxAgeSeconds: 600 }).exchange(await idToken({ auth_time: fresh }), { nonce: "n-1" })).passkey, true);
});
test("CONTROL: a subject too long for a Firebase uid is refused, never truncated", async () => {
    await refuses(bridge().exchange(await idToken({ sub: "x".repeat(130) }), { nonce: "n-1" }), "bad_subject");
});
test("configuration errors are thrown at creation", () => {
    assert.throws(() => createBridge({ issuer: "http://login.333.eco", clientId: CLIENT, auth }), TypeError);
    assert.throws(() => createBridge({ issuer: "https://login.333.eco/path", clientId: CLIENT, auth }), TypeError);
    assert.throws(() => createBridge({ issuer: ISS, clientId: "", auth }), TypeError);
    assert.throws(() => createBridge({ issuer: ISS, clientId: CLIENT, auth: {} }), TypeError);
});

test("CONTROL: an RS256 token is refused even when the issuer's key set also holds an RSA key", async () => {
    // During a rotation an issuer may publish a non-EC key; only the ES256 policy keeps an RS256 token out.
    const rsa = await generateKeyPair("RS256");
    const mixed = createLocalJWKSet({ keys: [jwk, { ...(await exportJWK(rsa.publicKey)), kid: "r1", alg: "RS256" }] });
    const t = await new SignJWT({ nonce: "n-1", amr: ["hwk"] }).setProtectedHeader({ alg: "RS256", kid: "r1" })
        .setIssuer(ISS).setAudience(CLIENT).setSubject("pw_x").setIssuedAt().setExpirationTime("5m").sign(rsa.privateKey);
    await refuses(createBridge({ issuer: ISS, clientId: CLIENT, auth, keys: mixed }).exchange(t, { nonce: "n-1" }), "invalid_token");
});
