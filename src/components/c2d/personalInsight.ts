/* eslint-disable security/detect-non-literal-fs-filename */
import axios from 'axios'
import { chmodSync, lstatSync, mkdirSync, rmSync } from 'fs'
import { z } from 'zod'
import type { PersonalInsightPolicy } from '../../@types/C2D/C2D.js'
import {
  assertPrivateDatasetConfiguration,
  downloadVerifiedJson,
  privateDatasetHttpsAgent
} from './privateDataset.js'
import { validateConsumerResultContract } from './consumerResult.js'

const RUN_ID = /^[0-9a-f]{32}$/
const JOB_ID = /^[0-9a-f]{64}$/
const SHA256 = /^[0-9a-f]{64}$/
const TITLE = 'My resting heart overview'
const SUMMARY =
  'This overview describes the qualifying resting recordings used for this result.'
const WARNING =
  'Personal overview only. Not a diagnosis or medical advice. Contact a qualified clinician if you have health concerns.'
const RFC3339_TIMESTAMP = z.string().max(35).datetime({ offset: true })

export class PersonalInsightError extends Error {
  public readonly terminal: boolean

  constructor(code: string, terminal: boolean = false) {
    super(code)
    this.name = 'PersonalInsightError'
    this.terminal = terminal
  }
}

function exactObject(value: unknown, keys: string[], code: string): any {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')
  ) {
    throw new PersonalInsightError(code)
  }
  return value
}

function isOpaqueToken(value: string): boolean {
  const components = value.split('.')
  if (
    components.length !== 2 ||
    components[0].length < 8 ||
    components[0].length > 128 ||
    components[1].length < 32 ||
    components[1].length > 128
  ) {
    return false
  }
  return components.every((component) =>
    [...component].every(
      (character) =>
        (character >= 'A' && character <= 'Z') ||
        (character >= 'a' && character <= 'z') ||
        (character >= '0' && character <= '9') ||
        character === '_' ||
        character === '-'
    )
  )
}

function endpoint(policy: PersonalInsightPolicy, pathname: string): string {
  return new URL(pathname, policy.crabUrl).toString()
}

function validTimestamp(value: unknown): boolean {
  return RFC3339_TIMESTAMP.safeParse(value).success
}

function isLocalProofHostname(hostname: string): boolean {
  const parts = hostname.split('.')
  const loopbackIpv4 =
    parts.length === 4 &&
    parts[0] === '127' &&
    parts.every(
      (part) =>
        part.length > 0 &&
        [...part].every((character) => character >= '0' && character <= '9') &&
        Number(part) <= 255
    )
  const singleLabel =
    !hostname.includes('.') &&
    hostname.length > 0 &&
    hostname.length <= 63 &&
    !hostname.startsWith('-') &&
    !hostname.endsWith('-') &&
    [...hostname].every(
      (character) =>
        (character >= 'a' && character <= 'z') ||
        (character >= '0' && character <= '9') ||
        character === '-'
    )
  return hostname === 'localhost' || loopbackIpv4 || singleLabel
}

function privateTransportPolicy(policy: PersonalInsightPolicy) {
  return {
    url: endpoint(policy, '/api/v1/internal/personal-insights/dataset'),
    maxBytes: policy.maxInputBytes,
    approvedAlgorithmImage: policy.approvedAlgorithmImage,
    bearerTokenEnv: policy.bearerTokenEnv,
    releaseId: '0'.repeat(64),
    tls: policy.tls
  }
}

export function assertPersonalInsightConfiguration(
  policy: PersonalInsightPolicy,
  environment: NodeJS.ProcessEnv = process.env
): void {
  const url = new URL(policy.crabUrl)
  if (
    url.protocol !== 'https:' &&
    !(
      policy.allowInsecureLocalProof === true &&
      url.protocol === 'http:' &&
      isLocalProofHostname(url.hostname)
    )
  ) {
    throw new PersonalInsightError('personal_insight_crab_transport_invalid')
  }
  if (policy.tls && url.protocol !== 'https:') {
    throw new PersonalInsightError('personal_insight_crab_transport_invalid')
  }
  if (!policy.ramWorkspaceRoot.startsWith('/dev/shm/')) {
    throw new PersonalInsightError('personal_insight_ram_workspace_invalid')
  }
  if (policy.bffBearerTokenEnv === policy.bearerTokenEnv) {
    throw new PersonalInsightError('personal_insight_bff_credential_invalid')
  }
  const bffBearerToken = environment[policy.bffBearerTokenEnv]
  if (
    typeof bffBearerToken !== 'string' ||
    bffBearerToken.length < 32 ||
    bffBearerToken.includes('\n') ||
    bffBearerToken.includes('\r')
  ) {
    throw new PersonalInsightError('personal_insight_bff_credential_invalid')
  }
  assertPrivateDatasetConfiguration(privateTransportPolicy(policy), environment)
}

async function postCrab(
  policy: PersonalInsightPolicy,
  pathname: string,
  body: Record<string, string>,
  environment: NodeJS.ProcessEnv
): Promise<any> {
  assertPersonalInsightConfiguration(policy, environment)
  try {
    const response = await axios({
      method: 'post',
      url: endpoint(policy, pathname),
      headers: {
        Accept: 'application/json',
        'Accept-Encoding': 'identity',
        Authorization: `Bearer ${environment[policy.bearerTokenEnv]}`,
        'Content-Type': 'application/json'
      },
      data: body,
      httpsAgent: privateDatasetHttpsAgent(privateTransportPolicy(policy)),
      timeout: 30000,
      maxRedirects: 0,
      decompress: false,
      validateStatus: () => true
    })
    if (response.status !== 200) {
      throw new PersonalInsightError(
        'personal_insight_crab_rejected',
        response.status === 410
      )
    }
    return response.data
  } catch (error) {
    if (error instanceof PersonalInsightError) throw error
    throw new PersonalInsightError('personal_insight_crab_unavailable')
  }
}

export async function claimPersonalInsightGrant(
  policy: PersonalInsightPolicy,
  grant: string,
  jobId: string,
  runId: string,
  environment: NodeJS.ProcessEnv = process.env
): Promise<string> {
  if (!isOpaqueToken(grant) || !JOB_ID.test(jobId) || !RUN_ID.test(runId)) {
    throw new PersonalInsightError('personal_insight_claim_invalid')
  }
  const body = exactObject(
    await postCrab(
      policy,
      '/api/v1/internal/personal-insights/grants/claim',
      { grant, jobId, runId },
      environment
    ),
    ['result'],
    'personal_insight_claim_invalid'
  )
  const result = exactObject(
    body.result,
    [
      'status',
      'expiresAt',
      'algorithmImageDigest',
      'inputSchema',
      'inputPolicy',
      'resultSchema',
      'resultProfile',
      'maximumRecordings',
      'audience',
      'historyId'
    ],
    'personal_insight_claim_invalid'
  )
  if (
    result.status !== 'claimed' ||
    !validTimestamp(result.expiresAt) ||
    result.algorithmImageDigest !== policy.approvedAlgorithmImage.split('@').at(-1) ||
    result.inputSchema !== policy.inputSchema ||
    result.inputPolicy !== policy.inputPolicy ||
    result.resultSchema !== policy.resultContract ||
    result.resultProfile !== policy.resultProfile ||
    result.maximumRecordings !== 16 ||
    result.audience !== policy.audience ||
    !SHA256.test(result.historyId)
  ) {
    throw new PersonalInsightError('personal_insight_claim_invalid')
  }
  return result.historyId
}

export async function completePersonalInsightRun(
  policy: PersonalInsightPolicy,
  grant: string,
  jobId: string,
  runId: string,
  resultSha256: string,
  environment: NodeJS.ProcessEnv = process.env
): Promise<void> {
  if (
    !isOpaqueToken(grant) ||
    !JOB_ID.test(jobId) ||
    !RUN_ID.test(runId) ||
    !SHA256.test(resultSha256)
  ) {
    throw new PersonalInsightError('personal_insight_completion_invalid')
  }
  let response: unknown
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      response = await postCrab(
        policy,
        '/api/v1/internal/personal-insights/runs/complete',
        { grant, jobId, runId, resultSha256 },
        environment
      )
      break
    } catch (error) {
      if (
        !(error instanceof PersonalInsightError) ||
        error.message !== 'personal_insight_crab_unavailable' ||
        attempt === 2
      ) {
        throw error
      }
      await new Promise((resolve) => setTimeout(resolve, 100 * (attempt + 1)))
    }
  }
  const body = exactObject(response, ['result'], 'personal_insight_completion_invalid')
  const result = exactObject(
    body.result,
    ['status', 'resultExpiresAt'],
    'personal_insight_completion_invalid'
  )
  if (result.status !== 'complete' || !validTimestamp(result.resultExpiresAt)) {
    throw new PersonalInsightError('personal_insight_completion_invalid')
  }
}

export async function revalidatePersonalInsightRun(
  policy: PersonalInsightPolicy,
  grant: string,
  jobId: string,
  runId: string,
  environment: NodeJS.ProcessEnv = process.env
): Promise<void> {
  if (!isOpaqueToken(grant) || !JOB_ID.test(jobId) || !RUN_ID.test(runId)) {
    throw new PersonalInsightError('personal_insight_revalidation_invalid')
  }
  const body = exactObject(
    await postCrab(
      policy,
      '/api/v1/internal/personal-insights/runs/revalidate',
      { grant, jobId, runId },
      environment
    ),
    ['result'],
    'personal_insight_revalidation_invalid'
  )
  const result = exactObject(
    body.result,
    ['status', 'jobId', 'runId'],
    'personal_insight_revalidation_invalid'
  )
  if (
    result.status !== 'authorized' ||
    result.jobId !== jobId ||
    result.runId !== runId
  ) {
    throw new PersonalInsightError('personal_insight_revalidation_invalid')
  }
}

export async function revalidatePersonalInsightHistory(
  policy: PersonalInsightPolicy,
  historyId: string,
  environment: NodeJS.ProcessEnv = process.env
): Promise<void> {
  if (!SHA256.test(historyId)) {
    throw new PersonalInsightError('personal_insight_revalidation_invalid')
  }
  const body = exactObject(
    await postCrab(
      policy,
      '/api/v1/internal/personal-insights/history/revalidate',
      { historyId },
      environment
    ),
    ['result'],
    'personal_insight_revalidation_invalid'
  )
  const result = exactObject(
    body.result,
    ['status', 'historyId'],
    'personal_insight_revalidation_invalid'
  )
  if (result.status !== 'authorized' || result.historyId !== historyId) {
    throw new PersonalInsightError('personal_insight_revalidation_invalid')
  }
}

export async function consumePersonalInsightCapability(
  policy: PersonalInsightPolicy,
  capability: string,
  runId: string,
  action: 'status' | 'result',
  environment: NodeJS.ProcessEnv = process.env
): Promise<string | null> {
  if (!isOpaqueToken(capability) || !RUN_ID.test(runId)) {
    throw new PersonalInsightError('personal_insight_capability_invalid')
  }
  const body = exactObject(
    await postCrab(
      policy,
      '/api/v1/internal/personal-insights/capabilities/consume',
      { capability, runId, action },
      environment
    ),
    ['result'],
    'personal_insight_capability_invalid'
  )
  const result = exactObject(
    body.result,
    ['status', 'action', 'runId', 'resultSha256'],
    'personal_insight_capability_invalid'
  )
  const checksumValid =
    action === 'status' ? result.resultSha256 === null : SHA256.test(result.resultSha256)
  if (
    result.status !== 'authorized' ||
    result.action !== action ||
    result.runId !== runId ||
    !checksumValid
  ) {
    throw new PersonalInsightError('personal_insight_capability_invalid')
  }
  return result.resultSha256
}

export async function consumePersonalInsightHistoryCapability(
  policy: PersonalInsightPolicy,
  capability: string,
  historyId: string,
  action: 'status' | 'result',
  environment: NodeJS.ProcessEnv = process.env
): Promise<string | null> {
  if (!isOpaqueToken(capability) || !SHA256.test(historyId)) {
    throw new PersonalInsightError('personal_insight_capability_invalid')
  }
  const body = exactObject(
    await postCrab(
      policy,
      '/api/v1/internal/personal-insights/history/capabilities/consume',
      { capability, historyId, action },
      environment
    ),
    ['result'],
    'personal_insight_capability_invalid'
  )
  const result = exactObject(
    body.result,
    ['status', 'action', 'historyId', 'resultSha256'],
    'personal_insight_capability_invalid'
  )
  const checksumValid =
    action === 'status' ? result.resultSha256 === null : SHA256.test(result.resultSha256)
  if (
    result.status !== 'authorized' ||
    result.action !== action ||
    result.historyId !== historyId ||
    !checksumValid
  ) {
    throw new PersonalInsightError('personal_insight_capability_invalid')
  }
  return result.resultSha256
}

export function downloadPersonalInsightDataset(
  policy: PersonalInsightPolicy,
  grant: string,
  jobId: string,
  destination: string,
  environment: NodeJS.ProcessEnv = process.env
): Promise<{ bytes: number; checksum: string }> {
  if (!isOpaqueToken(grant) || !JOB_ID.test(jobId)) {
    throw new PersonalInsightError('personal_insight_dataset_invalid')
  }
  assertPersonalInsightConfiguration(policy, environment)
  return downloadVerifiedJson(
    endpoint(policy, '/api/v1/internal/personal-insights/dataset'),
    destination,
    policy.maxInputBytes,
    {
      Accept: 'application/json',
      'Accept-Encoding': 'identity',
      Authorization: `Bearer ${environment[policy.bearerTokenEnv]}`,
      'X-Brainstem-Personal-Grant': grant,
      'X-Ocean-Compute-Job-Id': jobId
    },
    privateDatasetHttpsAgent(privateTransportPolicy(policy))
  )
}

const oneDecimal = (minimum: number, maximum: number) =>
  z
    .number()
    .finite()
    .min(minimum)
    .max(maximum)
    .refine((value) => Math.abs(value * 10 - Math.round(value * 10)) < 1e-9)
const metric = (label: string, unit: string, value: z.ZodTypeAny) =>
  z.object({ label: z.literal(label), value, unit: z.literal(unit) }).strict()
const personalResult = z
  .object({
    schema: z.literal('brainstem.c2d-result/v1'),
    status: z.literal('complete'),
    title: z.literal(TITLE),
    summary: z.literal(SUMMARY),
    metrics: z.tuple([
      metric('Qualifying recordings', 'count', z.number().int().min(1).max(16)),
      metric('Typical R-R interval', 'ms', oneDecimal(250, 2000)),
      metric('Typical resting rate', 'bpm', oneDecimal(30, 240))
    ]),
    charts: z
      .array(
        z
          .object({
            type: z.literal('line'),
            title: z.literal('Resting rate by recording'),
            x: z
              .object({
                label: z.literal('Recording'),
                values: z.array(z.number().int().min(1).max(16)).min(1).max(16)
              })
              .strict(),
            y: z
              .object({
                label: z.literal('Resting rate'),
                unit: z.literal('bpm')
              })
              .strict(),
            series: z
              .array(
                z
                  .object({
                    label: z.literal('Derived resting rate'),
                    values: z.array(oneDecimal(30, 240)).min(1).max(16)
                  })
                  .strict()
              )
              .length(1)
          })
          .strict()
      )
      .length(1),
    table: z.null(),
    warnings: z.tuple([z.literal(WARNING)]),
    provenance: z
      .object({
        algorithmVersion: z.literal('1.0.0'),
        algorithmImageDigest: z.string(),
        datasetSchemaVersion: z.literal('brainstem.personal-resting-rr/v1'),
        generatedAt: z.string().datetime({ offset: true })
      })
      .strict()
  })
  .strict()
  .superRefine((result, context) => {
    const count = result.metrics[0].value
    const x = result.charts[0].x.values
    const { values } = result.charts[0].series[0]
    if (
      x.length !== count ||
      values.length !== count ||
      x.some((value, index) => value !== index + 1)
    ) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'chart mismatch' })
    }
  })

const personalInput = z
  .object({
    schema: z.literal('brainstem.personal-resting-rr/v1'),
    policy: z.literal('brainstem.personal-resting-rr/latest-16/v1'),
    recordings: z
      .array(
        z
          .object({
            recordingType: z.literal('rest'),
            durationSeconds: z.number().int().min(300).max(86400),
            rrIntervalsMs: z
              .array(z.number().finite().min(250).max(2000))
              .min(4)
              .max(3600)
          })
          .strict()
      )
      .min(1)
      .max(16)
  })
  .strict()

export function validatePersonalInsightInput(bytes: Buffer): void {
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new PersonalInsightError('personal_insight_dataset_invalid')
  }
  if (!personalInput.safeParse(value).success) {
    throw new PersonalInsightError('personal_insight_dataset_invalid')
  }
}

export function validatePersonalInsightResult(
  bytes: Buffer,
  policy: PersonalInsightPolicy
): void {
  validateConsumerResultContract(bytes, {
    mode: 'singleJson',
    maxBytes: policy.maxResultBytes,
    resultContract: policy.resultContract
  })
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new PersonalInsightError('personal_insight_result_invalid')
  }
  const result = personalResult.safeParse(value)
  if (
    !result.success ||
    result.data.provenance.algorithmImageDigest !==
      policy.approvedAlgorithmImage.split('@').at(-1)
  ) {
    throw new PersonalInsightError('personal_insight_result_invalid')
  }
}

export function prepareRamWorkspace(
  policy: PersonalInsightPolicy,
  jobId: string
): string {
  if (!JOB_ID.test(jobId)) throw new PersonalInsightError('personal_insight_job_invalid')
  const root = lstatSync(policy.ramWorkspaceRoot)
  if (root.isSymbolicLink() || !root.isDirectory()) {
    throw new PersonalInsightError('personal_insight_ram_workspace_invalid')
  }
  const workspace = `${policy.ramWorkspaceRoot}/${jobId}`
  rmSync(workspace, { recursive: true, force: true })
  mkdirSync(workspace, { recursive: true, mode: 0o700 })
  return workspace
}

export function resetRamWorkspaceRoot(policy: PersonalInsightPolicy): void {
  assertPersonalInsightConfiguration(policy)
  rmSync(policy.ramWorkspaceRoot, { recursive: true, force: true })
  mkdirSync(policy.ramWorkspaceRoot, { recursive: true, mode: 0o700 })
  chmodSync(policy.ramWorkspaceRoot, 0o700)
}

export function purgeRamWorkspace(policy: PersonalInsightPolicy, jobId: string): void {
  if (JOB_ID.test(jobId)) {
    rmSync(`${policy.ramWorkspaceRoot}/${jobId}`, { recursive: true, force: true })
  }
}
