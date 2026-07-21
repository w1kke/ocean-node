# Slice 03 — fail-closed image scanning

## Contract

When image scanning is enabled, configuration names the severities that deny execution. Scanner infrastructure and report failures deny execution as well. Disabled scanning performs no scanner work.

## API seam

`scanImageRejectSeverities` is required and non-empty when `scanImages` is true. It accepts Trivy's supported severity names and drives both the scanner command and evaluation.

Scanner-image inspection/pull failures, database/update failures affecting the job scan, container creation/start errors, non-zero exit, oversized/empty output, malformed JSON, missing schema/results, or an unexpected report shape become an explicit terminal scan failure. A valid report containing a configured severity becomes `VulnerableImage`. Scanner containers are removed in `finally`.

## Runnable proof

Pure report tests cover severity combinations and malformed shapes. Docker-engine tests cover scanner absence/pull failure, non-zero exit, invalid output, a policy hit, a clean report, and the disabled path. Every denied case proves the algorithm volume/container is not created.

## Must stay green

- Marine's synthetic configuration keeps `scanImages: false`; this slice does not run a quota-consuming scan.
- Paid jobs reaching either scan-denial state enter the existing settlement/cancellation lifecycle rather than remaining locked indefinitely.
- Failure detail stays in operator logs; consumer status receives only the stable terminal state.
