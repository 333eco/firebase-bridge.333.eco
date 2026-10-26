/**
 * @333eco/firebase-bridge — turn a "Log in with HeartBank®" ID token into YOUR Firebase custom token.
 *
 * The flow: your app sends the person to login.333.eco (OpenID Connect, PKCE), gets an ID token back, and hands it
 * to a function you run. That function calls `exchange()`. The bridge verifies the token against login.333.eco's
 * published keys and mints a custom token for YOUR Firebase project, with YOUR service account.
 *
 * Properties this module keeps (and its tests prove by breaking them):
 *  - It never holds anyone else's key. B.333.eco never holds yours; you never need ours beyond the public JWKS.
 *  - Only ES256 is accepted. `alg: none`, HMAC and RSA tokens are refused (algorithm-confusion attacks).
 *  - The token must be for YOUR app (`aud`), from OUR issuer (`iss`), unexpired, and carry the nonce your own
 *    session issued. The bridge holds no state, so the nonce is single-use only if YOUR session discards it.
 *  - How the person logged in (`amr`) is copied into the custom token's claims, so your Firebase rules can require
 *    a passkey. `requirePasskey: true` refuses email- and SMS-code sessions outright.
 *  - The Firebase uid is derived from the pairwise subject, which is unique to your app: two apps never share it.
 */
import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";

/** The one method the bridge needs from firebase-admin's `Auth` (structural, so any firebase-admin version fits). */
export interface CustomTokenMinter {
    createCustomToken(uid: string, developerClaims?: object): Promise<string>;
}

export interface BridgeOptions {
    /** The issuer, exactly: "https://login.333.eco". */
    issuer: string;
    /** Your app's OpenID client id; the token's `aud` must equal it. */
    clientId: string;
    /** firebase-admin's `getAuth()` for YOUR project, or anything with `createCustomToken`. */
    auth: CustomTokenMinter;
    /** Refuse sessions that did not use a passkey. Default false. */
    requirePasskey?: boolean;
    /** Refuse a log-in older than this many seconds (`auth_time`). Default: no limit. */
    maxAgeSeconds?: number;
    /** Allowed clock skew in seconds. Default 60. */
    clockToleranceSeconds?: number;
    /** Override key lookup (tests, or a pinned key set). Default: the issuer's `/.well-known/jwks.json`. */
    keys?: JWTVerifyGetKey;
    /** Prefix for the Firebase uid. Default "hb:". */
    uidPrefix?: string;
}

export interface ExchangeResult {
    /** Give this to the client; it calls `signInWithCustomToken`. */
    customToken: string;
    /** The Firebase uid minted: `<uidPrefix><pairwise sub>`. */
    uid: string;
    /** True when the session's methods include a passkey (`hwk` or `swk`). */
    passkey: boolean;
    /** The methods the person used, as login.333.eco reported them. */
    amr: string[];
}

/** Why an exchange was refused. `code` is stable; `message` is for logs, never for end users. */
export class BridgeError extends Error {
    constructor(readonly code: "invalid_token" | "wrong_nonce" | "passkey_required" | "too_old" | "bad_subject", message: string) {
        super(message);
        this.name = "BridgeError";
    }
}

const PASSKEY_METHODS = new Set(["hwk", "swk"]);

export function createBridge(opts: BridgeOptions) {
    if (!/^https:\/\/[^/]+$/.test(opts.issuer)) throw new TypeError("issuer must be an https origin with no path, e.g. https://login.333.eco");
    if (!opts.clientId) throw new TypeError("clientId is required");
    if (!opts.auth || typeof opts.auth.createCustomToken !== "function") throw new TypeError("auth must provide createCustomToken");
    const keys = opts.keys ?? createRemoteJWKSet(new URL(`${opts.issuer}/.well-known/jwks.json`));
    const prefix = opts.uidPrefix ?? "hb:";

    async function exchange(idToken: string, check: { nonce: string }): Promise<ExchangeResult> {
        if (!check || !check.nonce) throw new BridgeError("wrong_nonce", "a nonce from your own session is required");
        let payload: JWTPayload;
        try {
            ({ payload } = await jwtVerify(idToken, keys, {
                issuer: opts.issuer,
                audience: opts.clientId,
                algorithms: ["ES256"],
                clockTolerance: opts.clockToleranceSeconds ?? 60,
                requiredClaims: ["sub", "iat", "exp", "nonce"],
            }));
        } catch (e) {
            throw new BridgeError("invalid_token", (e as Error).message);
        }
        // With several audiences, OpenID requires the authorized party to be us.
        if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== opts.clientId) {
            throw new BridgeError("invalid_token", "multiple audiences and azp is not this client");
        }
        if (payload.nonce !== check.nonce) throw new BridgeError("wrong_nonce", "nonce does not match this session");
        if (opts.maxAgeSeconds !== undefined) {
            const at = typeof payload.auth_time === "number" ? payload.auth_time : NaN;
            if (!Number.isFinite(at) || Date.now() / 1000 - at > opts.maxAgeSeconds + (opts.clockToleranceSeconds ?? 60)) {
                throw new BridgeError("too_old", "the log-in is older than maxAgeSeconds");
            }
        }
        const amr = Array.isArray(payload.amr) ? payload.amr.filter((m): m is string => typeof m === "string") : [];
        const passkey = amr.some((m) => PASSKEY_METHODS.has(m));
        if (opts.requirePasskey && !passkey) throw new BridgeError("passkey_required", "this app requires a passkey log-in");
        const sub = String(payload.sub);
        const uid = prefix + sub;
        // Firebase uids are at most 128 characters; a pairwise sub is far shorter, but refuse rather than truncate.
        if (!sub || uid.length > 128) throw new BridgeError("bad_subject", "subject missing or too long for a Firebase uid");
        const customToken = await opts.auth.createCustomToken(uid, {
            hb_amr: amr,
            hb_passkey: passkey,
            ...(typeof payload.acr === "string" ? { hb_acr: payload.acr } : {}),
        });
        return { customToken, uid, passkey, amr };
    }

    return { exchange };
}
