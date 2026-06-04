# gopay-sub-patcher

A lightweight state interceptor for navigating transient session-bound routing layers. Captures ambient context from the active viewport and synthesizes a deterministic entry point, resilient to mid-flow topology shifts, environmental drift, or session discontinuities.

> Assumes familiarity with runtime inspection primitives. Confine usage to locally-scoped identity surfaces.

## Surface Layer

- `checkout-link-only.js`: Minimal extraction surface — emits resolved session tokens and the derived path.

- `gopay-long-link.js`: Observational variant with inline telemetry for tracing request/response lifecycle.

- `gopay_pure_signer.py`: Peripheral signatory utilities; consult as needed.

## Protocol Layer

The `gopay-auto-protocol/` directory houses a headless, pure-Python implementation of the identity provisioning and authentication handshake — no runtime inspection or instrumented binary required.

- `gopay_protocol.py`: Core protocol substrate. Constructs device fingerprints, synthesizes request signatures across multiple signing backends (null, captured-replay, adb-oracle, pure-Python, enhanced), handles PIN tokenization via symmetric block ciphers, and orchestrates the full HTTP lifecycle against the upstream identity and payment surfaces.

- `full_pure_signup_pin.py`: End-to-end state machine for identity provisioning. Acquires a transient communication channel, drives the OTP verification loop, negotiates signup/login handshakes, binds a PIN credential, and persists session state.

- `pure_pin_only.py`: Minimal entrypoint — accepts a PIN operand and delegates to the full state machine with sensible defaults.

- `smscloud_client.py`: Transient communication channel broker. Manages number acquisition, OTP polling, and order lifecycle for out-of-band verification codes.

## Invocation

### Path A: Runtime Injection

1. Establish an authenticated session within the relevant scope.

2. Invoke the inspection layer (`F12` or equivalent).

3. Navigate to the **Console** evaluation context. Inject the contents of `checkout-link-only.js`.

4. Materialize the emitted URI within a compatible execution environment.

### Path B: Structural Reference

For integration into bespoke pipelines, inspect the request synthesis, response decomposition, and output derivation logic within `gopay-long-link.js`. Adapt to local topology.

### Path C: Headless Provisioning

```bash
# Minimal — acquire channel, verify, provision identity, bind PIN
python3 gopay-auto-protocol/pure_pin_only.py --pin 123456

# Full control over each phase
python3 gopay-auto-protocol/full_pure_signup_pin.py --buy --pin 123456 --xe-mode enhanced
```

Signing backends are selectable via `--xe-mode`: `none`, `captured`, `adb-oracle`, `pure`, `enhanced`. The default `enhanced` mode operates entirely without device instrumentation.

## Constraints

- Derived paths are session-scoped; do not externalize.

- Maintain sovereignty over identity artifacts, credential surfaces, and execution contexts.

- Upstream schemas, response envelopes, and gating heuristics are mutable. Longitudinal stability is not contractually bound.

- This substrate exists for observational and structural study purposes. Operative responsibility rests with the integrator.
