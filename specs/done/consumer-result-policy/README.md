# Consumer result policy

## Purpose

Ocean Node treats compute results as an explicit release boundary. An authenticated consumer can learn its job state and retrieve only artifacts selected by the environment policy; operational logs and private job configuration remain on the operator side. Environments that require image scanning also deny execution when the scanner cannot prove an image satisfies the configured policy.

This boundary exists because compute ownership is not the same as permission to inspect infrastructure output. Wallet authentication identifies a caller, but it does not make algorithm logs, signed URLs, configuration, payment state, or incidental output safe to disclose.

## Decisions and reasons

`consumerResultPolicy` is required for every Docker environment. An explicit `archive` mode preserves intentional legacy workloads, while `singleJson` means exactly one bounded `/data/outputs/result.json`. There is no omission default: defaulting to the broader legacy behavior would turn a configuration mistake into disclosure.

The policy contributes to the environment identifier. Changing the release contract therefore creates a different environment instead of silently widening or narrowing a running job. Operators must drain jobs using the old environment before migration.

Node validates only the generic release envelope: filename, regular-file type, uniqueness, byte limit, strict UTF-8, and a JSON object. Domain semantics remain with the reviewed algorithm and consumer application. This keeps the Node reusable and prevents a Brainstem-only policy from becoming infrastructure behavior.

Image scanning has one severity policy shared by the Trivy command and report evaluator. Individual scan execution, decoding, and validated-shape failures are denial states, not clean results. Empty result arrays remain valid clean reports; database freshness and scanner deployment are operator controls rather than claims inferred from the report.

## Invariants

- Public compute jobs are allowlisted projections. Adding a private database field cannot make it public by omission.
- The authenticated consumer projection intentionally includes ownership and lifecycle fields (`owner`, DIDs, job and agreement IDs, timestamps, status, environment, duration/queue limits, result descriptors, exit/OOM details, and caller-provided `metadata`). Metadata is not a private channel: clients must never place participant data, credentials, private URLs, or infrastructure details in it.
- Stored logs never receive consumer result indices. The live-log command remains wire-compatible but is closed to consumers.
- Bearer tokens are bound to their stored wallet address. Status and result filters cannot claim a different consumer identity.
- Missing artifacts return not found, while authorization failures remain authorization failures.
- Strict output never falls back to an archive or accepts a second, nested, linked, or special tar entry. Validation finishes before local or remote publication begins; local publication uses atomic replacement, while remote atomicity depends on the selected backend.
- Local and remote release paths consume the same validated result bytes.
- Enabled scanning requires a non-empty supported severity list and stops before algorithm volumes or containers when scanning fails or rejects the image.
- Disabled scanning creates no Trivy cache, pull, update timer, or scanner container. This matters for local pilots that intentionally have no scanning guarantee.
- For a scan-denied paid job, Node submits a zero-value claim for a live Enterprise Escrow lock; an expired lock uses the existing contract cancellation path. Contract-level lock closure and payer-balance behavior remain an integration responsibility.

## Code and test map

- Public job projection and result routing: `omitDBComputeFieldsFromComputeJob`, `ComputeGetStatusHandler`, `ComputeGetResultHandler`, `C2DEngineDocker.getComputeJobResult`, and `ComputeGetStreamableLogsHandler`.
- Environment policy and identity hashing: `ConsumerResultPolicy`, `C2DEnvironmentConfigSchema`, and `C2DEngineDocker.getComputeEnvironments`.
- Strict result validation: `readSingleJsonResultArchive` in `src/components/c2d/consumerResult.ts` and the result publication paths in `C2DEngineDocker`.
- Scanner policy: `evaluateTrivyReport` in `src/components/c2d/imageScan.ts` and `scanImage` in `C2DEngineDocker`.
- Regression coverage: `src/test/integration/compute.test.ts` plus `computeResultAccess.test.ts`, `consumerResult.test.ts`, `imageScan.test.ts`, and `config.test.ts` under `src/test/unit/`. The unit seam drives strict local and remote publication.
- Operator configuration contract: `docs/env.md`.

## Rejected approaches

- Removing a blacklist of known private job fields was rejected because each new database field would be public until someone remembered to hide it.
- Keeping consumer log access for signed wallets was rejected because a valid signature proves identity, not job authorization or safe log contents.
- Letting log presence determine result indices was rejected because it made the consumer contract unstable and turned logs into retrievable artifacts.
- Making strict output an optional route flag or silently falling back to `outputs.tar` was rejected because caller choice and configuration mistakes could widen disclosure.
- Parsing any JSON-looking substring from Trivy output or treating scanner failure as clean was rejected because both convert untrusted or absent evidence into permission to execute.

## Operational boundary

This policy is necessary but not sufficient for real health data. Production still requires an enabled and exercised scanner policy, current vulnerability data, compute-host isolation, consent-filtered ingestion, reviewed immutable algorithms, monitoring, retention, and deployment controls. The Trivy container currently expects the Docker daemon socket at `/var/run/docker.sock` inside the scanner; custom or remote Docker deployments must verify that bind reaches the intended daemon. Marketplace publication, chain ordering, participant identity, and domain-result validation remain separate owners.
