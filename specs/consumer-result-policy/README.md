# Consumer result policy

## Next Agent Prompt

Status: complete, last updated 2026-07-21.

All three slices are complete on `feature/consumer-result-policy`. Marine's strict local result checkpoint must remain pinned to the final Node commit. Keep Brainstem schema logic, marketplace, chain, Crab, mobile, and CI publication work out of this feature.

- [x] [01 — consumer job boundary](slices/01-consumer-job-boundary.md)
- [x] [02 — explicit result release](slices/02-explicit-result-release.md)
- [x] [03 — fail-closed image scanning](slices/03-fail-closed-image-scanning.md)

## Goal

Before any real health data reaches Ocean compute, a consumer must be able to retrieve only the approved bounded result. Algorithm, configuration, image, publish, and live logs remain available to the Node operator but never through the consumer API. Required image scanning must deny execution when the scanner cannot produce a valid report or when the configured severity policy is hit.

## Measured baseline

- Job status currently advertises four stored logs before `outputs.tar`, so result indices change with log presence.
- The result endpoint serves every advertised log to owners and additional viewers.
- Live-log authentication proves only that a wallet signed; it does not prove the wallet owns or may view the job.
- Local and remote output both archive all of `/data/outputs`.
- Scanner-image errors, missing reports, and malformed reports can be treated as clean. Trivy asks for HIGH and CRITICAL findings, but the evaluator blocks only CRITICAL.

## Single-owner invariants

- Node owns generic filename, file-type, JSON-syntax, size, and consumer-egress enforcement.
- The per-environment `consumerResultPolicy` is the only output-release policy. Do not add route flags or a Brainstem-only mode.
- `archive` is an explicit compatibility mode. `singleJson` always means exactly `/data/outputs/result.json`; it has no configurable path.
- The environment ID incorporates its result policy, so a policy change cannot silently widen an already-running job. Operators drain old jobs before migration.
- Operators keep local logs. There is no replacement operator HTTP log API in this feature.
- Brainstem result semantics remain owned by the algorithm contract, reviewed immutable image, and DeSciLab validator.
- Scanner severity configuration is the only vulnerability threshold. The Trivy query and report evaluator use the same set.

## Firewalls

- No consumer opt-in can expose logs.
- No fallback from a failed strict result to an archive.
- No new package is needed; use the repository's existing tar and stream tooling.
- Marine may keep `scanImages: false` for the synthetic local pilot. That path must not pull Trivy or update its database.
- Real health data remains blocked until all three slices and the local strict-result rerun are green.
- Marketplace publication, ordering, payment, Crab export, participant identity, and mobile behavior are out of scope.

## Review map

- Gate A: job status is a stable allowlisted projection; stored and live logs are unavailable to consumer APIs; missing indices return 404.
- Gate B: every environment explicitly selects `archive` or `singleJson`; the Brainstem pilot releases only bounded valid `result.json`, including remote output.
- Gate C: enabled scans fail closed on infrastructure/report failures and reject the configured severities before the algorithm container starts.

## Compatibility decision

This is an intentional deployment migration. Existing environments must select `archive`; Brainstem selects `singleJson`. There is no omission default because a silent legacy fallback would make a missing production setting disclose more data. Consumer live logs are removed globally rather than retained behind an unsafe compatibility flag.
