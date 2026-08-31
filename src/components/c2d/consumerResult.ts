import { Readable, Transform } from 'stream'
import { pipeline } from 'node:stream/promises'
import { createHash } from 'node:crypto'
import * as tarStream from 'tar-stream'
import { z } from 'zod'
import type {
  ConsumerResultPolicy,
  DBComputeResultValidation
} from '../../@types/C2D/C2D.js'

const MAX_ARCHIVE_OVERHEAD_BYTES = 64 * 1024
const PLAIN_TEXT =
  /^(?!.*(?:[A-Za-z][A-Za-z0-9+.-]*:\S+|(?:^|\s)\/\/\S+|(?:^|\s)[Ww][Ww][Ww]\.|<[^>]*>|!\[|\]\())[^\r\n]*$/

const plainText = (max: number) => z.string().min(1).max(max).regex(PLAIN_TEXT)
const label = plainText(80)
const unit = plainText(24)

function isSemanticVersion(value: string): boolean {
  const plus = value.split('+')
  if (plus.length > 2) return false
  const dash = plus[0].split('-')
  const core = dash.shift()?.split('.') ?? []
  if (core.length !== 3) return false
  if (
    core.some(
      (part) => !/^[0-9]+$/.test(part) || (part.length > 1 && part.startsWith('0'))
    )
  ) {
    return false
  }
  const prerelease = dash.join('-')
  if (dash.length > 0 && prerelease.length === 0) return false
  if (plus[1] !== undefined && plus[1].length === 0) return false
  const prereleaseValid = (prerelease ? prerelease.split('.') : []).every(
    (part) =>
      part.length > 0 &&
      /^[0-9A-Za-z-]+$/.test(part) &&
      (!/^[0-9]+$/.test(part) || part === '0' || !part.startsWith('0'))
  )
  const buildValid = (plus[1]?.split('.') ?? []).every(
    (part) => part.length > 0 && /^[0-9A-Za-z-]+$/.test(part)
  )
  return prereleaseValid && buildValid
}

const metric = z
  .object({ label, value: z.number().finite(), unit: unit.optional() })
  .strict()
const axis = z
  .object({
    label,
    unit: unit.optional(),
    values: z
      .array(z.union([z.number().finite(), plainText(64)]))
      .min(1)
      .max(500)
  })
  .strict()
const valueAxis = z.object({ label, unit: unit.optional() }).strict()
const series = z
  .object({ label, values: z.array(z.number().finite()).min(1).max(500) })
  .strict()
const chart = z
  .object({
    type: z.enum(['line', 'bar', 'scatter', 'histogram']),
    title: plainText(160),
    x: axis,
    y: valueAxis,
    series: z.array(series).min(1).max(8)
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.type === 'scatter' &&
      value.x.values.some((item) => typeof item !== 'number')
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['x', 'values'],
        message: 'scatter x values must be numeric'
      })
    }
    for (const [index, item] of value.series.entries()) {
      if (item.values.length !== value.x.values.length) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['series', index, 'values'],
          message: 'series length must match x values'
        })
      }
    }
  })
const table = z
  .object({
    title: plainText(160),
    columns: z
      .array(z.object({ label, unit: unit.optional() }).strict())
      .min(1)
      .max(10),
    rows: z
      .array(
        z
          .array(
            z.union([
              z.number().finite(),
              z.string().min(1).max(128).regex(PLAIN_TEXT),
              z.null()
            ])
          )
          .min(1)
          .max(10)
      )
      .min(1)
      .max(100)
  })
  .strict()
  .superRefine((value, context) => {
    for (const [index, row] of value.rows.entries()) {
      if (row.length !== value.columns.length) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['rows', index],
          message: 'row length must match columns'
        })
      }
    }
  })
const provenance = z
  .object({
    algorithmVersion: z.string().min(1).max(64).refine(isSemanticVersion),
    algorithmImageDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    datasetSchemaVersion: z
      .string()
      .min(1)
      .max(80)
      .regex(/^[a-z0-9._/-]+$/),
    generatedAt: z.string().max(40).datetime({ offset: true })
  })
  .strict()
const reliabilityEstimate = z
  .object({
    unit: z.enum(['hours', 'bpm']),
    p10: z.number().finite(),
    p25: z.number().finite(),
    p50: z.number().finite(),
    p75: z.number().finite(),
    p90: z.number().finite(),
    icc11: z.number().finite().min(-1).max(1),
    icc11Ci95: z.tuple([
      z.number().finite().min(-1).max(1),
      z.number().finite().min(-1).max(1)
    ]),
    meanReliabilityByNights: z
      .array(
        z
          .object({
            nights: z.number().int().min(1).max(7),
            estimate: z.number().finite().min(-1).max(1),
            ci95: z.tuple([
              z.number().finite().min(-1).max(1),
              z.number().finite().min(-1).max(1)
            ])
          })
          .strict()
      )
      .length(7),
    minimumNightsForLowerCi80: z.union([
      z.number().int().min(1).max(7),
      z.literal('not_established_within_7')
    ]),
    medianWithinPersonCvPercent: z.number().finite().min(0),
    medianWithinPersonCvPercentCi95: z.tuple([
      z.number().finite().min(0),
      z.number().finite().min(0)
    ])
  })
  .strict()
  .superRefine((value, context) => {
    if (
      !(
        value.p10 <= value.p25 &&
        value.p25 <= value.p50 &&
        value.p50 <= value.p75 &&
        value.p75 <= value.p90
      ) ||
      value.icc11Ci95[0] > value.icc11Ci95[1] ||
      value.medianWithinPersonCvPercentCi95[0] >
        value.medianWithinPersonCvPercentCi95[1] ||
      value.meanReliabilityByNights.some(
        (item, index) => item.nights !== index + 1 || item.ci95[0] > item.ci95[1]
      )
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'sleep reliability estimates are inconsistent'
      })
    }
  })
const reliabilityBands = z
  .object({
    durationHours: z.tuple([z.number().finite(), z.number().finite()]),
    sleepingRateBpm: z.tuple([z.number().finite(), z.number().finite()]),
    acceptedPercent: z.tuple([z.number().finite(), z.number().finite()])
  })
  .strict()
const sleepReliabilityReference = z
  .object({
    schema: z.literal('brainstem.sleep-reliability-reference/v1'),
    version: z.enum(['generated-review-candidate-v1', 'review-required-v1']),
    analysisId: z.literal('brainstem.sleep-baseline/v2'),
    sourceType: z.enum(['generated_fixture', 'approved_real_cohort']),
    sourceReleaseSha256: z.string().regex(/^[0-9a-f]{64}$/),
    sourceSnapshotSha256: z.string().regex(/^[0-9a-f]{64}$/),
    inclusionContract: z.literal(
      'brainstem.full-night-nightly-features/exact-distinct-7/v1'
    ),
    algorithmVersion: z.literal('0.3.0'),
    algorithmImageDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    candidateManifestSha256: z.literal(
      'b9bcc30891ffa7368f6169947b9aea9e2bb968a4a4db56287bd1ffde98d94073'
    ),
    referenceYear: z.literal(2026),
    minimumParticipants: z.literal(20),
    ageBands: z.tuple([
      z.literal('under_30'),
      z.literal('30_44'),
      z.literal('45_59'),
      z.literal('60_plus')
    ]),
    reliability: z
      .object({
        durationHours: reliabilityEstimate,
        sleepingRateBpm: reliabilityEstimate
      })
      .strict(),
    scopes: z
      .array(
        z
          .object({
            scopeId: z.string().regex(/^[0-9a-f]{64}$/),
            dimensions: z.array(z.enum(['ageBand', 'gender', 'region'])).max(3),
            participantCountBand: z.enum(['20 to 49', '50 to 99', '100 or more']),
            bands: reliabilityBands
          })
          .strict()
      )
      .min(1)
      .max(64),
    sha256: z.string().regex(/^[0-9a-f]{64}$/)
  })
  .strict()
  .superRefine((value, context) => {
    const scopeIds = new Set(value.scopes.map((scope) => scope.scopeId))
    if (
      scopeIds.size !== value.scopes.length ||
      !value.scopes.some((scope) => scope.dimensions.length === 0) ||
      value.scopes.some((scope) =>
        Object.values(scope.bands).some(([low, high]) => low > high)
      )
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'sleep reliability reference scopes are inconsistent'
      })
    }
  })
const sleepReliabilityResult = z
  .object({
    schema: z.literal('brainstem.c2d-result/v1'),
    status: z.enum(['complete', 'insufficient_data']),
    title: plainText(160),
    summary: plainText(1000),
    metrics: z.array(metric).max(12),
    charts: z.array(chart).max(8),
    table: table.nullable(),
    warnings: z.array(plainText(500)).max(8),
    provenance: z
      .object({
        analysisId: z.literal('brainstem.sleep-reliability-benchmark/v1'),
        algorithmVersion: z.literal('0.3.0'),
        algorithmImageDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
        candidateManifestSha256: z.literal(
          'b9bcc30891ffa7368f6169947b9aea9e2bb968a4a4db56287bd1ffde98d94073'
        ),
        datasetSchemaVersion: z.literal('brainstem.sleep-nightly-features-cohort/v1'),
        selectorPolicy: z.literal(
          'brainstem.full-night-nightly-features/exact-distinct-7/v1'
        ),
        generatedAt: z.string().max(40).datetime({ offset: true }),
        estimator: z.literal(
          'ICC(1,1) balanced one-way random-effects absolute agreement'
        ),
        bootstrap: z.literal('10000 deterministic participant-level resamples'),
        referenceSha256: z
          .string()
          .regex(/^[0-9a-f]{64}$/)
          .optional()
      })
      .strict(),
    reference: sleepReliabilityReference.nullable()
  })
  .strict()
  .superRefine((value, context) => {
    const hasResult = value.metrics.length > 0 || value.charts.length > 0 || value.table
    if (
      (value.status === 'complete' &&
        (!hasResult ||
          !value.reference ||
          value.provenance.referenceSha256 !== value.reference.sha256)) ||
      (value.status !== 'complete' &&
        (hasResult || value.reference !== null || value.provenance.referenceSha256))
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'sleep reliability result status is inconsistent'
      })
    }
  })
const brainstemResult = z
  .object({
    schema: z.literal('brainstem.c2d-result/v1'),
    status: z.enum(['complete', 'insufficient_data', 'failed']),
    title: plainText(160),
    summary: plainText(1000),
    metrics: z.array(metric).max(12),
    charts: z.array(chart).max(8),
    table: table.nullable(),
    warnings: z.array(plainText(500)).max(8),
    provenance
  })
  .strict()
  .superRefine((value, context) => {
    const hasResult = value.metrics.length > 0 || value.charts.length > 0 || value.table
    if (value.status === 'complete' && !hasResult) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'complete result must contain an aggregate result'
      })
    }
    if (value.status !== 'complete' && hasResult) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'non-complete result must not contain aggregate values'
      })
    }
  })

const insightResult = z
  .object({
    schema: z.literal('brainstem.insight-result/v1'),
    analysisId: z
      .string()
      .max(100)
      .regex(/^[a-z0-9.-]+\/v[1-9][0-9]*$/),
    scope: z.enum(['cohort', 'personal']),
    status: z.enum(['complete', 'insufficient_data', 'failed']),
    abstentionReason: z
      .enum([
        'insufficient_quality',
        'insufficient_coverage',
        'privacy_floor',
        'uncalibrated_device',
        'outside_validated_population',
        'out_of_distribution',
        'model_uncertainty',
        'reference_unavailable'
      ])
      .nullable(),
    evidence: z
      .object({
        tier: z.enum([
          'E0_candidate',
          'E1_public_reproduced',
          'E2_brainstem_compatible_exploratory',
          'E3_brainstem_validated_research'
        ]),
        useClass: z.enum([
          'methods_only',
          'exploratory_research',
          'protocol_bound_research'
        ]),
        clinicalUse: z.literal('prohibited')
      })
      .strict(),
    paperClassification: z
      .object({
        decision: z.enum(['classified', 'abstained', 'not_applicable']),
        label: plainText(80).nullable(),
        score: z.number().finite().min(0).max(1).nullable()
      })
      .strict()
      .nullable(),
    title: plainText(160),
    summary: plainText(1000),
    metrics: z.array(metric).max(12),
    charts: z.array(chart).max(8),
    table: table.nullable(),
    warnings: z.array(plainText(500)).max(8),
    provenance: provenance
      .extend({
        candidateManifestSha256: z.string().regex(/^[0-9a-f]{64}$/),
        referenceSha256: z
          .string()
          .regex(/^[0-9a-f]{64}$/)
          .nullable(),
        referenceScopeSha256: z
          .string()
          .regex(/^[0-9a-f]{64}$/)
          .optional(),
        referenceScopeDimensions: z
          .enum(['age_gender_region', 'age_gender', 'age', 'all'])
          .optional(),
        referenceScopeBroadened: z.boolean().optional()
      })
      .strict()
  })
  .strict()
  .superRefine((value, context) => {
    const hasResult = value.metrics.length > 0 || value.charts.length > 0 || value.table
    if (value.status === 'complete' && !hasResult) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'complete result must contain an aggregate result'
      })
    }
    if (value.status !== 'complete' && hasResult) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'non-complete result must not contain aggregate values'
      })
    }
    if (
      value.paperClassification?.decision === 'classified' &&
      value.evidence.tier !== 'E3_brainstem_validated_research'
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'classification requires E3 evidence'
      })
    }
    if (
      value.paperClassification &&
      value.paperClassification.decision !== 'classified' &&
      (value.paperClassification.label !== null ||
        value.paperClassification.score !== null)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'abstained classifications cannot contain a label or score'
      })
    }
  })

export function validateConsumerResultContract(
  bytes: Buffer,
  policy: ConsumerResultPolicy,
  expectedAlgorithmImageDigest?: string
): DBComputeResultValidation | undefined {
  if (policy.mode !== 'singleJson' || !policy.resultContract) return undefined
  if (
    !Number.isSafeInteger(policy.maxBytes) ||
    policy.maxBytes < 1 ||
    bytes.length > policy.maxBytes
  ) {
    throw new Error('result.json exceeds the configured size limit')
  }

  let value: unknown
  try {
    value = JSON.parse(bytes.toString('utf8'))
  } catch {
    throw new Error('result.json is not valid JSON')
  }
  const result =
    policy.resultContract === 'brainstem.insight-result/v1'
      ? insightResult.safeParse(value)
      : z.union([brainstemResult, sleepReliabilityResult]).safeParse(value)
  if (!result.success) {
    throw new Error(`result.json does not match ${policy.resultContract}`)
  }
  if (
    expectedAlgorithmImageDigest &&
    result.data.provenance.algorithmImageDigest !== expectedAlgorithmImageDigest
  ) {
    throw new Error('result.json algorithm digest does not match execution')
  }
  return {
    contract: policy.resultContract,
    status: result.data.status,
    billable: ['complete', 'insufficient_data'].includes(result.data.status),
    algorithmVersion: result.data.provenance.algorithmVersion,
    algorithmImageDigest: result.data.provenance.algorithmImageDigest,
    datasetSchemaVersion: result.data.provenance.datasetSchemaVersion
  }
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (value !== null && typeof value === 'object') {
    return `{${Object.entries(value)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(',')}}`
  }
  return JSON.stringify(value)
}

export function validateSleepReliabilityResult(
  bytes: Buffer,
  expectedImageDigest: string
): void {
  let value: unknown
  try {
    value = JSON.parse(bytes.toString('utf8'))
  } catch {
    throw new Error('result.json is not valid JSON')
  }
  const parsed = sleepReliabilityResult.safeParse(value)
  if (!parsed.success) {
    throw new Error('result.json does not match the sleep reliability policy')
  }
  if (
    parsed.data.provenance.algorithmImageDigest !== expectedImageDigest ||
    (parsed.data.reference &&
      parsed.data.reference.algorithmImageDigest !== expectedImageDigest)
  ) {
    throw new Error('result.json algorithm digest does not match execution')
  }
  if (parsed.data.reference) {
    const { sha256, ...reference } = parsed.data.reference
    const actual = createHash('sha256')
      .update(`${canonicalJson(reference)}\n`)
      .digest('hex')
    if (actual !== sha256) {
      throw new Error('result.json reference digest is invalid')
    }
  }
}

export function validateReviewedInsightResult(
  bytes: Buffer,
  expected: {
    analysisId: string
    scope: 'cohort' | 'personal'
    algorithmVersion: string
    algorithmImageDigest: string
    inputSchema: string
    candidateManifestSha256: string
    referenceSha256: string | null
    evidenceTier: string
    useClass: string
    clinicalUse: 'prohibited'
  }
): void {
  validateConsumerResultContract(
    bytes,
    {
      mode: 'singleJson',
      maxBytes: bytes.length,
      resultContract: 'brainstem.insight-result/v1'
    },
    expected.algorithmImageDigest
  )
  const result = JSON.parse(bytes.toString('utf8'))
  const complete = result.status === 'complete'
  if (
    result.analysisId !== expected.analysisId ||
    result.scope !== expected.scope ||
    result.evidence?.tier !== expected.evidenceTier ||
    result.evidence?.useClass !== expected.useClass ||
    result.evidence?.clinicalUse !== expected.clinicalUse ||
    (complete &&
      (result.paperClassification?.decision !== 'not_applicable' ||
        result.paperClassification.label !== null ||
        result.paperClassification.score !== null)) ||
    (!complete && result.paperClassification !== null) ||
    result.provenance?.algorithmVersion !== expected.algorithmVersion ||
    result.provenance?.datasetSchemaVersion !== expected.inputSchema ||
    result.provenance?.candidateManifestSha256 !== expected.candidateManifestSha256 ||
    result.provenance?.referenceSha256 !== (complete ? expected.referenceSha256 : null)
  ) {
    throw new Error('result.json does not match the reviewed Insight policy')
  }
}

export async function readSingleJsonResultArchive(
  archive: Readable,
  maxBytes: number
): Promise<Buffer> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new Error('Invalid singleJson result size limit')
  }

  const extract = tarStream.extract()
  let archiveBytes = 0
  let entryCount = 0
  let result: Buffer = null
  let failure: Error = null

  const archiveLimiter = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      archiveBytes += chunk.length
      if (archiveBytes > maxBytes + MAX_ARCHIVE_OVERHEAD_BYTES) {
        callback(new Error('Result archive exceeds the configured size limit'))
        return
      }
      callback(null, chunk)
    }
  })

  extract.on('entry', (header, stream, next) => {
    entryCount += 1
    const chunks: Buffer[] = []
    let entryBytes = 0

    if (entryCount !== 1) failure ??= new Error('Result archive has extra entries')
    if (header.name !== 'result.json') {
      failure ??= new Error('Result archive must contain only result.json')
    }
    if (header.type !== 'file') {
      failure ??= new Error('result.json must be a regular file')
    }
    if (!Number.isSafeInteger(header.size) || header.size < 0 || header.size > maxBytes) {
      failure ??= new Error('result.json exceeds the configured size limit')
    }

    stream.on('data', (chunk: Buffer) => {
      entryBytes += chunk.length
      if (entryBytes > maxBytes) {
        failure ??= new Error('result.json exceeds the configured size limit')
      } else {
        chunks.push(Buffer.from(chunk))
      }
    })
    stream.once('error', (error) => {
      failure ??= error
    })
    stream.once('end', () => {
      if (header.size !== entryBytes) {
        failure ??= new Error('result.json archive entry is truncated')
      }
      if (entryCount === 1 && !failure) result = Buffer.concat(chunks)
      next()
    })
  })

  await pipeline(archive, archiveLimiter, extract)

  if (failure) throw failure
  if (entryCount !== 1 || !result) {
    throw new Error('Result archive must contain exactly one result.json file')
  }

  let decoded: string
  try {
    decoded = new TextDecoder('utf-8', { fatal: true }).decode(result)
  } catch {
    throw new Error('result.json is not valid UTF-8')
  }

  let value: unknown
  try {
    value = JSON.parse(decoded)
  } catch {
    throw new Error('result.json is not valid JSON')
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('result.json must contain a JSON object')
  }

  return result
}
