# @333eco/firebase-bridge

Accept **Log in with HeartBank®** in a Firebase app. Your app sends the person to `login.333.eco` (OpenID Connect),
gets an ID token back, and gives it to a function you run. The bridge verifies the token and mints a custom token for
**your** Firebase project, with **your** service account. HeartBank never holds your keys.

```js
import { getAuth } from "firebase-admin/auth";
import { createBridge } from "@333eco/firebase-bridge";

const bridge = createBridge({
  issuer: "https://login.333.eco",
  clientId: "<your client id>",
  auth: getAuth(),
  requirePasskey: false,          // true refuses email- and SMS-code log-ins
});

// in your HTTPS function, with the nonce YOUR session issued (and then discards):
const { customToken, passkey } = await bridge.exchange(idToken, { nonce });
// the client calls signInWithCustomToken(auth, customToken)
```

**What it refuses** (each one is a test that is broken on purpose to prove it): tokens signed by a key the issuer did
not publish · tampered tokens · `alg: none`, HMAC and RSA tokens (ES256 only) · tokens for another app (`aud`) or
another issuer (`iss`) · expired tokens · a nonce from another session · several audiences without `azp` = you ·
log-ins older than `maxAgeSeconds` · subjects too long for a Firebase uid (refused, never truncated).

**What your rules get:** the custom token carries `hb_amr` (how the person logged in), `hb_passkey` (true for a
passkey), and `hb_acr` when present. Require a passkey where it matters:

```
allow write: if request.auth.token.hb_passkey == true;
```

The Firebase uid is `hb:<subject>`. The subject is **pairwise**: unique to your app, so two apps can never link a person
through it.

⚠️ The bridge holds no state. A nonce is single-use only if your session discards it after one exchange.

CC0-1.0. Status: 0.x — `login.333.eco` is not live yet; the API may change before 1.0.
