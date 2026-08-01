# Governed external tool-call example

`src/governed-tool-call.mjs` is a small host-owned integration for the GoMission bounty. It wraps a consequential provider function with `@trust-graduation/core` and a deterministic action fingerprint.

The boundary is immediately before `provider(action)`:

1. Normalize action class, tool, target, and JSON input.
2. Require `principal`, `requestedBy`, and `scope`; reject unknown action classes.
3. Ask Trust Graduation for a decision and return its approval packet. The provider is not called.
4. Bind the approval to the SHA-256 fingerprint of the exact action.
5. Consume the pending approval before calling the provider, so replay is rejected.
6. Record a machine-readable result receipt correlated to the decision and fingerprint.

The tests use an in-memory sandbox provider and never touch production credentials or a live external system. Run them with:

```bash
npm install
npm test
```

The blind Mission Gate baseline must be run only after GoMission explicitly selects a contributor and confirms the payment route, as requested in the bounty issue.
