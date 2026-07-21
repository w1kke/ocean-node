# Slice 01 — consumer job boundary

## Contract

Consumer job APIs expose a stable public job projection and output artifacts only. Stored logs and live stdout/stderr are operator-only for every environment.

## API seam

- `omitDBComputeFieldsFromComputeJob` constructs the public `ComputeJob` shape from an allowlist rather than deleting a partial blacklist.
- Docker `getResults` advertises output only; it never assigns a consumer result index to a log.
- `computeStreamableLogs` remains registered for wire compatibility but returns a fixed 403 after normal request validation.
- `computeResult` returns 404 when an index is unavailable and preserves authorization errors without manufacturing an empty 200.

## Runnable proof

Focused unit tests create a job containing dataset URLs, algorithm configuration, payment data, additional viewers, and all four log files. The public job omits internal fields; output remains retrievable by authorized viewers; no stored or live log is retrievable.

## Must stay green

Existing output archive behavior remains unchanged in this slice. HTTP and P2P use the same handlers. Operator-local log creation and cleanup continue.
