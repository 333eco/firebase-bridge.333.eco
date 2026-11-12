# @333eco/firebase-bridge

Accept **Log in with HeartBank®** in a Firebase app. **Only Firebase apps need this package.** Any other app uses an
OpenID library directly: [developer docs and tested samples](https://login.333.eco/developers/docs).

Your app sends the person to `login.333.eco` (OpenID Connect), gets an ID token back, and gives it to a function you run. The bridge verifies the token and mints a custom token for
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

⚠️ With single sign-on, `auth_time` is the person's FIRST log-in, so a `maxAgeSeconds` here can refuse a normal returning
user. If you need a recent log-in, send `max_age` in the request, so login asks them again.

⚠️ `hb_passkey` says how THIS log-in happened. A person can link email, phone and passkeys into one account, so the same
uid can arrive with `hb_passkey` true or false. Check it on each token, never store it on the user. If someone joins two
accounts, the joined account's uid stops arriving and they reach you under the other one.

`CC0-1.0 OR Apache-2.0`, your choice (see `LICENSE`). Status: 0.x, live at `login.333.eco`; the API may change before 1.0.
