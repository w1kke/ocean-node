# Slice 02 — explicit result release

## Contract

Every Docker compute environment explicitly selects `archive` or `singleJson`. Strict mode releases exactly one bounded, regular, syntactically valid `result.json` and nothing else.

## API seam

`consumerResultPolicy` is a discriminated environment configuration:

- `archive` preserves arbitrary `outputs.tar` for intentional legacy workloads;
- `singleJson` requires a positive bounded `maxBytes` and fixes the container path and consumer filename to `result.json`.

The policy contributes to the environment ID. Result capture requests only the exact file from Docker, accepts exactly one regular tar entry with that exact basename, caps archive and content bytes, decodes strict UTF-8, parses a JSON object, and publishes bytes only after all checks pass. Local retrieval and remote upload consume the same validated bytes.

## Runnable proof

Unit fixtures cover valid JSON, extra sibling files, missing output, duplicate/nested entries, links and special entries, invalid UTF-8/JSON, truncation, and one byte over the limit. A Marine rerun proves the current Brainstem image produces a direct JSON result at index zero and DeSciLab still renders it.

## Must stay green

- Strict failure becomes `ResultsFetchFailed`; it never falls back to an archive or publishes partial bytes.
- Remote output receives only the validated JSON, not `/data/outputs`.
- The legacy archive path remains available only through explicit `archive` configuration.
- Node validates the generic envelope, not `brainstem.c2d-result/v1` semantics.
