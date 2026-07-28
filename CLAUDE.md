# Ocean Enterprise Node contributor guidance

This repository executes approved compute and stores bounded results. It does
not decide participant identity, consent, study membership, or cohort
eligibility.

## Safe work

```bash
npm run lint
npm run type-check
npm run build
npm run test:unit
npm run test:integration:light
```

Use generated inputs. Preserve single-fetch, size-bound, checksum-verified
dataset delivery and opaque job correlation. Compute must remain isolated,
network-restricted, and unable to return raw input or participant identifiers.

## Protected boundaries

- Do not accept a client-supplied arbitrary dataset URL, algorithm image, or
  output destination.
- Do not weaken image approval, result validation, output limits, retention,
  or privacy thresholds.
- Docker socket access, runtime networking, secrets, production endpoints, and
  result-policy changes require security-owner review.
- Do not run `npm run quickstart`, load/stress tests, release commands, image
  publication, or a compute job against shared infrastructure without explicit
  approval.

Existing upstream contribution rules and `CODEOWNERS` still apply. Brainstem
integration changes also require DataUnion owner review.

