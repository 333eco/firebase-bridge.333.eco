# CLAUDE.md — firebase-bridge.333.eco

`@333eco/firebase-bridge` — public, CC0, one runtime dependency (`jose`, EXACT pin). Spec: the private
`333eco/b.333.eco` SPEC.md §2.1 and §9. Doctrine is canonical in memory (`project_b_origin`); memory wins.

- ⛔ **The suite's value is its refusals.** Every guard has a CONTROL test; a new guard needs one that is seen to fail.
- ⚠️ **Mutation-test with an apply check** (anchor found exactly once) — a mutation that does not apply reads as a pass.
  Measured 2026-10-26: four mutations (algorithm list, nonce, requirePasskey, multi-audience azp) each fail the suite.
- ⚠️ A `undefined` argument triggers a JS default parameter — a "no amr" control once silently carried a passkey.
- ⛔ Never widen `algorithms` beyond ES256; never truncate a subject; never add server-side state.
- Publish = bump `version` on main; CI gates on the tests and needs the `NPM_TOKEN` repo secret. Verify with `npm view`.
