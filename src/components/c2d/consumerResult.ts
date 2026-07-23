import { Readable, Transform } from 'stream'
import { pipeline } from 'node:stream/promises'
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

export function validateConsumerResultContract(
  bytes: Buffer,
  policy: ConsumerResultPolicy
): DBComputeResultValidation | undefined {
  if (policy.mode !== 'singleJson' || !policy.resultContract) return undefined

  let value: unknown
  try {
    value = JSON.parse(bytes.toString('utf8'))
  } catch {
    throw new Error('result.json is not valid JSON')
  }
  const result = brainstemResult.safeParse(value)
  if (!result.success) {
    throw new Error('result.json does not match brainstem.c2d-result/v1')
  }
  return {
    contract: policy.resultContract,
    status: result.data.status,
    billable: ['complete', 'insufficient_data'].includes(result.data.status)
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
