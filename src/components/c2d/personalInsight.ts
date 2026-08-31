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
import {
  validateConsumerResultContract,
  validateReviewedInsightResult
} from './consumerResult.js'

const RUN_ID = /^[0-9a-f]{32}$/
const JOB_ID = /^[0-9a-f]{64}$/
const SHA256 = /^[0-9a-f]{64}$/
const METHODS_CANDIDATE_SHA256 =
  '15dbf8544c87d81c06f5e512b00e9fe39dd6431dd1a4079a97da68a3f92721c1'
const SAMPLE_ENTROPY_CANDIDATE_SHA256 =
  '65002ab13f02f812c611085c0295b81dc90ec7ffacc79f9ff4927e81e9070bdd'
const SLEEP_BASELINE_CANDIDATE_SHA256 =
  'bb270d52974bd51d5c2e62f53b5215b057b274afa0c57b1a280a98ddf8d8a7c9'
const SLEEP_BASELINE_V2_CANDIDATE_SHA256 =
  'b7fb1cd6d31f76f393044604933a45d762d6ee56dfc197c50c498aad3594a7fd'
const SLEEP_BASELINE_V2_REFERENCE_SHA256 =
  '9eab9cb0cbddee8305b04c1d7cc41133193465c553c5e49d1b24942ab073b235'
const OVERNIGHT_CHANGE_CANDIDATE_SHA256 =
  '56e996b4cde15689b7524e7e9427b7fc67dd722d77493fd1daac67d421d90907'
const REST_REPEATABILITY_CANDIDATE_SHA256 =
  '09e22348e350bb9e1da7183929675f7d67e718eb183075a7735c5513468905dd'
const STANDING_RESPONSE_CANDIDATE_SHA256 =
  'ee503af519ed241f1f7ec965b58ad41b38c622c71a43e3f44c86743722ac4217'
const STANDING_RESPONSE_REFERENCE_SHA256 =
  'ffba0c6772fba94d5a18ec130cd5d0b080cb4f819d8c3fc4034a2b2dfd578979'
const GUIDED_BREATHING_CANDIDATE_SHA256 =
  'e64490c6539db744350ee761db4a1fedffd6f9f631f8814480a684c1fdc4931d'
const GUIDED_BREATHING_REFERENCE_SHA256 =
  '45d96a1769a6cd8e51c74ff603bc4589427fb8bfc2b6f69e65c4037c1c1e6232'
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

function isExactNamedPolicy(policy: PersonalInsightPolicy): boolean {
  if (policy.useClass !== 'methods_only' || policy.clinicalUse !== 'prohibited') {
    return false
  }
  if (policy.analysisId === 'brainstem.personal-resting-heart-overview/v1') {
    return (
      policy.maximumRecordings === 16 &&
      policy.algorithmVersion === '1.0.0' &&
      policy.inputSchema === 'brainstem.personal-resting-rr/v1' &&
      policy.inputPolicy === 'brainstem.personal-resting-rr/latest-16/v1' &&
      policy.resultContract === 'brainstem.c2d-result/v1' &&
      policy.resultProfile === 'brainstem.personal-resting-heart-overview/v1' &&
      policy.evidenceTier === 'E2_brainstem_compatible_exploratory' &&
      policy.candidateManifestSha256 === null &&
      policy.approvedManifestSha256 === null &&
      policy.referenceSha256 === null
    )
  }
  if (policy.analysisId === 'brainstem.resting-hrv-methods/v1') {
    return (
      policy.maximumRecordings === 16 &&
      policy.algorithmVersion === '0.1.0' &&
      policy.inputSchema === 'brainstem.personal-resting-hrv-methods/v1' &&
      policy.inputPolicy === 'brainstem.personal-resting-hrv-methods/latest-16/v1' &&
      policy.resultContract === 'brainstem.insight-result/v1' &&
      policy.resultProfile === 'brainstem.resting-hrv-methods-personal/v1' &&
      policy.evidenceTier === 'E2_brainstem_compatible_exploratory' &&
      policy.candidateManifestSha256 === METHODS_CANDIDATE_SHA256 &&
      typeof policy.approvedManifestSha256 === 'string' &&
      SHA256.test(policy.approvedManifestSha256) &&
      typeof policy.referenceSha256 === 'string' &&
      SHA256.test(policy.referenceSha256)
    )
  }
  if (policy.analysisId === 'brainstem.resting-rr-sample-entropy/v1') {
    return (
      policy.maximumRecordings === 4 &&
      policy.algorithmVersion === '0.1.0' &&
      policy.inputSchema === 'brainstem.personal-resting-sample-entropy/v1' &&
      policy.inputPolicy === 'brainstem.personal-resting-sample-entropy/latest-4/v1' &&
      policy.resultContract === 'brainstem.insight-result/v1' &&
      policy.resultProfile === 'brainstem.resting-sample-entropy-personal/v1' &&
      policy.evidenceTier === 'E2_brainstem_compatible_exploratory' &&
      policy.candidateManifestSha256 === SAMPLE_ENTROPY_CANDIDATE_SHA256 &&
      typeof policy.approvedManifestSha256 === 'string' &&
      SHA256.test(policy.approvedManifestSha256) &&
      typeof policy.referenceSha256 === 'string' &&
      SHA256.test(policy.referenceSha256)
    )
  }
  if (policy.analysisId === 'brainstem.overnight-heart-rate-change/v1') {
    return (
      policy.maximumRecordings === 9 &&
      policy.algorithmVersion === '0.2.0' &&
      policy.inputSchema === 'brainstem.personal-overnight-heart-rate-change/v2' &&
      policy.inputPolicy ===
        'brainstem.personal-overnight-heart-rate-change/latest-distinct-9-movement/v2' &&
      policy.resultContract === 'brainstem.insight-result/v1' &&
      policy.resultProfile === 'brainstem.overnight-heart-rate-change-personal/v2' &&
      policy.candidateManifestSha256 === OVERNIGHT_CHANGE_CANDIDATE_SHA256 &&
      typeof policy.approvedManifestSha256 === 'string' &&
      SHA256.test(policy.approvedManifestSha256) &&
      policy.referenceSha256 === null &&
      policy.evidenceTier === 'E1_public_reproduced'
    )
  }
  if (policy.analysisId === 'brainstem.sleep-baseline/v2') {
    return (
      policy.maximumRecordings === 9 &&
      policy.algorithmVersion === '0.1.0' &&
      policy.inputSchema === 'brainstem.personal-sleep-nightly-features/v1' &&
      policy.inputPolicy === 'brainstem.personal-sleep-baseline/latest-distinct-9/v2' &&
      policy.resultContract === 'brainstem.insight-result/v1' &&
      policy.resultProfile === 'brainstem.sleep-baseline-personal/v2' &&
      policy.candidateManifestSha256 === SLEEP_BASELINE_V2_CANDIDATE_SHA256 &&
      typeof policy.approvedManifestSha256 === 'string' &&
      SHA256.test(policy.approvedManifestSha256) &&
      policy.referenceSha256 === SLEEP_BASELINE_V2_REFERENCE_SHA256 &&
      policy.evidenceTier === 'E2_brainstem_compatible_exploratory'
    )
  }
  if (policy.analysisId === 'brainstem.resting-hrv-repeatability/v1') {
    return (
      policy.maximumRecordings === 7 &&
      policy.algorithmVersion === '0.1.0' &&
      policy.inputSchema === 'brainstem.personal-resting-hrv-repeatability/v1' &&
      policy.inputPolicy ===
        'brainstem.personal-resting-hrv-repeatability/latest-distinct-7/v1' &&
      policy.resultContract === 'brainstem.insight-result/v1' &&
      policy.resultProfile === 'brainstem.resting-hrv-repeatability-personal/v1' &&
      policy.candidateManifestSha256 === REST_REPEATABILITY_CANDIDATE_SHA256 &&
      typeof policy.approvedManifestSha256 === 'string' &&
      SHA256.test(policy.approvedManifestSha256) &&
      policy.referenceSha256 === null &&
      policy.evidenceTier === 'E0_candidate'
    )
  }
  if (policy.analysisId === 'brainstem.standing-heart-rate-response/v1') {
    return (
      policy.maximumRecordings === 7 &&
      policy.algorithmVersion === '0.1.0' &&
      policy.inputSchema === 'brainstem.personal-standing-heart-rate-response/v1' &&
      policy.inputPolicy ===
        'brainstem.personal-standing-heart-rate-response/latest-7/v1' &&
      policy.resultContract === 'brainstem.insight-result/v1' &&
      policy.resultProfile === 'brainstem.standing-heart-rate-response-personal/v1' &&
      policy.candidateManifestSha256 === STANDING_RESPONSE_CANDIDATE_SHA256 &&
      typeof policy.approvedManifestSha256 === 'string' &&
      SHA256.test(policy.approvedManifestSha256) &&
      policy.referenceSha256 === STANDING_RESPONSE_REFERENCE_SHA256 &&
      policy.evidenceTier === 'E2_brainstem_compatible_exploratory'
    )
  }
  if (policy.analysisId === 'brainstem.guided-breathing-response/v1') {
    return (
      policy.maximumRecordings === 7 &&
      policy.algorithmVersion === '0.1.0' &&
      policy.inputSchema === 'brainstem.personal-guided-breathing-response/v1' &&
      policy.inputPolicy ===
        'brainstem.personal-guided-breathing-response/protocol-6-5-0-5-0/latest-7/v1' &&
      policy.resultContract === 'brainstem.insight-result/v1' &&
      policy.resultProfile === 'brainstem.guided-breathing-response-personal/v1' &&
      policy.candidateManifestSha256 === GUIDED_BREATHING_CANDIDATE_SHA256 &&
      typeof policy.approvedManifestSha256 === 'string' &&
      SHA256.test(policy.approvedManifestSha256) &&
      policy.referenceSha256 === GUIDED_BREATHING_REFERENCE_SHA256 &&
      policy.evidenceTier === 'E2_brainstem_compatible_exploratory'
    )
  }
  return (
    policy.maximumRecordings === 7 &&
    policy.analysisId === 'brainstem.sleep-baseline/v1' &&
    policy.algorithmVersion === '0.2.0' &&
    policy.inputSchema === 'brainstem.personal-sleep-baseline/v2' &&
    policy.inputPolicy === 'brainstem.personal-sleep-baseline/latest-7/v2' &&
    policy.resultContract === 'brainstem.insight-result/v1' &&
    policy.resultProfile === 'brainstem.sleep-baseline-personal/v1' &&
    policy.evidenceTier === 'E2_brainstem_compatible_exploratory' &&
    policy.candidateManifestSha256 === SLEEP_BASELINE_CANDIDATE_SHA256 &&
    typeof policy.approvedManifestSha256 === 'string' &&
    SHA256.test(policy.approvedManifestSha256) &&
    typeof policy.referenceSha256 === 'string' &&
    SHA256.test(policy.referenceSha256)
  )
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
  if (!isExactNamedPolicy(policy)) {
    throw new PersonalInsightError('personal_insight_policy_invalid')
  }
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
      { analysisId: policy.analysisId, grant, jobId, runId },
      environment
    ),
    ['result'],
    'personal_insight_claim_invalid'
  )
  const result = exactObject(
    body.result,
    [
      'status',
      'analysisId',
      'algorithmVersion',
      'expiresAt',
      'algorithmImageDigest',
      'inputSchema',
      'inputPolicy',
      'resultSchema',
      'resultProfile',
      'candidateManifestSha256',
      'approvedManifestSha256',
      'referenceSha256',
      'evidenceTier',
      'useClass',
      'clinicalUse',
      'maximumRecordings',
      'audience',
      'historyId'
    ],
    'personal_insight_claim_invalid'
  )
  if (
    result.status !== 'claimed' ||
    result.analysisId !== policy.analysisId ||
    result.algorithmVersion !== policy.algorithmVersion ||
    !validTimestamp(result.expiresAt) ||
    result.algorithmImageDigest !== policy.approvedAlgorithmImage.split('@').at(-1) ||
    result.inputSchema !== policy.inputSchema ||
    result.inputPolicy !== policy.inputPolicy ||
    result.resultSchema !== policy.resultContract ||
    result.resultProfile !== policy.resultProfile ||
    result.candidateManifestSha256 !== policy.candidateManifestSha256 ||
    result.approvedManifestSha256 !== policy.approvedManifestSha256 ||
    result.referenceSha256 !== policy.referenceSha256 ||
    result.evidenceTier !== policy.evidenceTier ||
    result.useClass !== policy.useClass ||
    result.clinicalUse !== policy.clinicalUse ||
    result.maximumRecordings !== policy.maximumRecordings ||
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
        { analysisId: policy.analysisId, grant, jobId, runId, resultSha256 },
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
      { analysisId: policy.analysisId, grant, jobId, runId },
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
      { analysisId: policy.analysisId, historyId },
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
      { analysisId: policy.analysisId, capability, runId, action },
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
      { analysisId: policy.analysisId, capability, historyId, action },
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
      'X-Brainstem-Analysis-Id': policy.analysisId,
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

const legacyPersonalInput = z
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

const methodsRecording = z
  .object({
    recordingType: z.literal('rest'),
    durationSeconds: z.number().int().min(300).max(360),
    rrIntervalsMs: z.array(z.number().finite().min(250).max(2000)).min(180).max(3600)
  })
  .strict()
  .superRefine((recording, context) => {
    const representedSeconds =
      recording.rrIntervalsMs.reduce((total, value) => total + value, 0) / 1000
    if (
      Math.abs(representedSeconds - recording.durationSeconds) >
      Math.max(5, recording.durationSeconds * 0.1)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'interval duration does not match durationSeconds'
      })
    }
  })

const methodsPersonalInput = z
  .object({
    schema: z.literal('brainstem.personal-resting-hrv-methods/v1'),
    recordings: z.array(methodsRecording).min(1).max(16)
  })
  .strict()

const sampleEntropyPersonalInput = z
  .object({
    schema: z.literal('brainstem.personal-resting-sample-entropy/v1'),
    recordings: z
      .array(
        z
          .object({
            recordingType: z.literal('rest'),
            durationSeconds: z.number().int().min(300).max(360),
            rrIntervalsMs: z
              .array(z.number().finite().min(300).max(2000))
              .min(240)
              .max(900)
          })
          .strict()
          .superRefine((recording, context) => {
            const representedSeconds =
              recording.rrIntervalsMs.reduce((total, value) => total + value, 0) / 1000
            if (
              Math.abs(representedSeconds - recording.durationSeconds) >
              Math.max(5, recording.durationSeconds * 0.1)
            ) {
              context.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'interval duration does not match durationSeconds'
              })
            }
          })
      )
      .min(1)
      .max(4)
  })
  .strict()

const sleepRecording = z
  .object({
    recordingType: z.literal('sleep'),
    durationSeconds: z
      .number()
      .int()
      .min(5 * 60 * 60)
      .max(12 * 60 * 60),
    intervalSemantics: z.literal('detector_rr_unclassified'),
    allowedUse: z.literal('private_descriptive_self_only'),
    quality: z
      .object({
        observedIntervalCount: z.number().int().min(9000).max(172800),
        acceptedIntervalCount: z.number().int().min(9000).max(172800),
        acceptedFraction: z.number().finite().min(0.95).max(1),
        durationCoverageRatio: z.number().finite().min(0.9).max(1.1),
        normalToNormalProvenance: z.literal('unverified'),
        officialMethodInputCompatible: z.literal(false)
      })
      .strict(),
    rrIntervalsMs: z.array(z.number().finite().min(250).max(2000)).min(9000).max(172800)
  })
  .strict()
  .superRefine((recording, context) => {
    const accepted = recording.rrIntervalsMs.length
    const fraction = accepted / recording.quality.observedIntervalCount
    const coverage =
      recording.rrIntervalsMs.reduce((total, value) => total + value, 0) /
      1000 /
      recording.durationSeconds
    if (
      recording.quality.acceptedIntervalCount !== accepted ||
      recording.quality.observedIntervalCount < accepted ||
      Math.abs(recording.quality.acceptedFraction - fraction) > 0.000001 ||
      Math.abs(recording.quality.durationCoverageRatio - coverage) > 0.000001
    ) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'quality mismatch' })
    }
  })

const personalReferenceProfile = z
  .object({
    schema: z.literal('brainstem.reference-profile/v1'),
    referenceYear: z.literal(2026),
    ageBand: z.enum(['under_30', '30_44', '45_59', '60_plus']).nullable(),
    gender: z.enum(['female', 'male']).nullable(),
    region: z
      .enum([
        'North America',
        'Europe',
        'South East Asia',
        'East Asia',
        'Middle East',
        'South America',
        'Central Asia',
        'Other'
      ])
      .nullable()
  })
  .strict()

const sleepBaselinePersonalInput = z
  .object({
    schema: z.literal('brainstem.personal-sleep-baseline/v2'),
    policy: z.literal('brainstem.personal-sleep-baseline/latest-7/v2'),
    referenceProfile: personalReferenceProfile,
    recordings: z.array(sleepRecording).min(1).max(7)
  })
  .strict()

const sleepNightlyFeature = z
  .object({
    schema: z.literal('brainstem.sleep-nightly-features/v1'),
    nightIndex: z.number().int().min(1).max(9),
    durationSeconds: z
      .number()
      .int()
      .min(5 * 60 * 60)
      .max(12 * 60 * 60),
    observedIntervalCount: z.number().int().min(9000).max(172800),
    acceptedIntervalCount: z.number().int().min(9000).max(172800),
    intervalSumMs: z.number().finite().positive(),
    durationCoverageRatio: z.number().finite().min(0.9).max(1.1),
    normalToNormalProvenance: z.literal('unverified'),
    officialMethodInputCompatible: z.literal(false)
  })
  .strict()
  .superRefine((night, context) => {
    if (
      night.acceptedIntervalCount > night.observedIntervalCount ||
      night.acceptedIntervalCount / night.observedIntervalCount < 0.95 ||
      night.intervalSumMs < 250 * night.acceptedIntervalCount ||
      night.intervalSumMs > 2000 * night.acceptedIntervalCount ||
      Math.abs(
        night.durationCoverageRatio - night.intervalSumMs / 1000 / night.durationSeconds
      ) > 0.000001
    ) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'night quality mismatch' })
    }
  })

const sleepBaselineV2PersonalInput = z
  .object({
    schema: z.literal('brainstem.personal-sleep-nightly-features/v1'),
    policy: z.literal('brainstem.personal-sleep-baseline/latest-distinct-9/v2'),
    referenceProfile: personalReferenceProfile,
    nights: z.array(sleepNightlyFeature).min(7).max(9)
  })
  .strict()
  .superRefine((input, context) => {
    if (input.nights.some((night, index) => night.nightIndex !== index + 1)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'night sequence mismatch'
      })
    }
  })

const overnightNight = z
  .object({
    nightIndex: z.number().int().min(1).max(9),
    durationSeconds: z
      .number()
      .int()
      .min(5 * 60 * 60)
      .max(12 * 60 * 60),
    observedIntervalCount: z.number().int().min(9000).max(172800),
    acceptedIntervalCount: z.number().int().min(9000).max(172800),
    intervalSumMs: z.number().finite().positive(),
    durationCoverageRatio: z.number().finite().min(0.9).max(1.1),
    movementCoverageFraction: z.number().finite().min(0.8).max(1),
    alignedHeartRateSampleFraction: z.number().finite().min(0.8).max(1),
    movementEventCount: z.number().int().min(0),
    movementEventRatePerHour: z.number().finite().min(0),
    quietWindowProportion: z.number().finite().min(0).max(1),
    quietMeanHeartRateBpm: z.number().finite().min(20).max(250).nullable(),
    movementMeanHeartRateBpm: z.number().finite().min(20).max(250).nullable(),
    normalToNormalProvenance: z.literal('unverified'),
    officialMethodInputCompatible: z.literal(false)
  })
  .strict()
  .superRefine((night, context) => {
    if (
      night.acceptedIntervalCount > night.observedIntervalCount ||
      night.acceptedIntervalCount / night.observedIntervalCount < 0.95 ||
      Math.abs(
        night.durationCoverageRatio - night.intervalSumMs / 1000 / night.durationSeconds
      ) > 0.000001 ||
      night.movementEventCount > night.durationSeconds ||
      Math.abs(
        night.movementEventRatePerHour -
          night.movementEventCount / (night.durationSeconds / 3600)
      ) > 0.000001 ||
      (night.quietWindowProportion === 0) !== (night.quietMeanHeartRateBpm === null) ||
      (night.movementEventCount === 0) !== (night.movementMeanHeartRateBpm === null)
    ) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'night quality mismatch' })
    }
  })

const overnightPersonalInput = z
  .object({
    schema: z.literal('brainstem.personal-overnight-heart-rate-change/v2'),
    policy: z.literal(
      'brainstem.personal-overnight-heart-rate-change/latest-distinct-9-movement/v2'
    ),
    movementSchema: z.literal('brainstem.normalized-movement/v1'),
    movementThresholdMilliG: z.literal(100),
    nights: z.array(overnightNight).length(9)
  })
  .strict()
  .superRefine((input, context) => {
    if (input.nights.some((night, index) => night.nightIndex !== index + 1)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'night sequence mismatch'
      })
    }
  })

const repeatabilityPersonalInput = z
  .object({
    schema: z.literal('brainstem.personal-resting-hrv-repeatability/v1'),
    policy: z.literal(
      'brainstem.personal-resting-hrv-repeatability/latest-distinct-7/v1'
    ),
    recordings: z.array(methodsRecording).min(2).max(7)
  })
  .strict()

const standingResponsePersonalInput = z
  .object({
    schema: z.literal('brainstem.personal-standing-heart-rate-response/v1'),
    policy: z.literal('brainstem.personal-standing-heart-rate-response/latest-7/v1'),
    recordings: z
      .array(
        z
          .object({
            recordingType: z.literal('posture'),
            durationSeconds: z.number().int().min(295).max(305),
            rrIntervalsMs: z
              .array(z.number().finite().min(300).max(2000))
              .min(148)
              .max(1100)
          })
          .strict()
          .superRefine((recording, context) => {
            const representedSeconds =
              recording.rrIntervalsMs.reduce((total, value) => total + value, 0) / 1000
            if (
              representedSeconds < 295 ||
              representedSeconds > 305 ||
              Math.abs(representedSeconds - recording.durationSeconds) > 5
            ) {
              context.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'interval duration does not match durationSeconds'
              })
            }
          })
      )
      .min(1)
      .max(7)
  })
  .strict()

const guidedBreathingProtocol = z
  .object({
    rateCPM: z.literal(6),
    ih: z.literal(5),
    ip: z.literal(0),
    eh: z.literal(5),
    ep: z.literal(0)
  })
  .strict()

const guidedBreathingPersonalInput = z
  .object({
    schema: z.literal('brainstem.personal-guided-breathing-response/v1'),
    policy: z.literal(
      'brainstem.personal-guided-breathing-response/protocol-6-5-0-5-0/latest-7/v1'
    ),
    protocol: guidedBreathingProtocol,
    recordings: z
      .array(
        z
          .object({
            recordingIndex: z.number().int().min(1).max(7),
            recordingType: z.literal('exercise'),
            durationSeconds: z.number().int().min(120).max(1800),
            protocol: guidedBreathingProtocol,
            rrIntervalsMs: z
              .array(z.number().finite().min(300).max(2000))
              .min(1)
              .max(6000)
          })
          .strict()
          .superRefine((recording, context) => {
            const coverage =
              recording.rrIntervalsMs.reduce((total, value) => total + value, 0) /
              1000 /
              recording.durationSeconds
            if (coverage < 0.9 || coverage > 1.1) {
              context.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'interval duration does not match durationSeconds'
              })
            }
          })
      )
      .min(1)
      .max(7)
  })
  .strict()
  .superRefine((input, context) => {
    const indices = input.recordings.map((recording) => recording.recordingIndex)
    if (new Set(indices).size !== indices.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'recording indices must be unique'
      })
    }
  })

export function validatePersonalInsightInput(
  bytes: Buffer,
  policy: PersonalInsightPolicy
): void {
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new PersonalInsightError('personal_insight_dataset_invalid')
  }
  const input =
    policy.inputSchema === 'brainstem.personal-resting-hrv-methods/v1'
      ? methodsPersonalInput
      : policy.inputSchema === 'brainstem.personal-resting-sample-entropy/v1'
        ? sampleEntropyPersonalInput
        : policy.inputSchema === 'brainstem.personal-overnight-heart-rate-change/v2'
          ? overnightPersonalInput
          : policy.inputSchema === 'brainstem.personal-resting-hrv-repeatability/v1'
            ? repeatabilityPersonalInput
            : policy.inputSchema === 'brainstem.personal-standing-heart-rate-response/v1'
              ? standingResponsePersonalInput
              : policy.inputSchema === 'brainstem.personal-guided-breathing-response/v1'
                ? guidedBreathingPersonalInput
                : policy.inputSchema === 'brainstem.personal-sleep-nightly-features/v1'
                  ? sleepBaselineV2PersonalInput
                  : policy.inputSchema === 'brainstem.personal-sleep-baseline/v2'
                    ? sleepBaselinePersonalInput
                    : legacyPersonalInput
  if (!input.safeParse(value).success) {
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
  if (policy.resultContract === 'brainstem.insight-result/v1') {
    try {
      validateReviewedInsightResult(bytes, {
        analysisId: policy.analysisId,
        scope: 'personal',
        algorithmVersion: policy.algorithmVersion,
        algorithmImageDigest: policy.approvedAlgorithmImage.split('@').at(-1),
        inputSchema: policy.inputSchema,
        candidateManifestSha256: policy.candidateManifestSha256,
        referenceSha256: policy.referenceSha256,
        evidenceTier: policy.evidenceTier,
        useClass: policy.useClass,
        clinicalUse: policy.clinicalUse
      })
      if (policy.analysisId === 'brainstem.sleep-baseline/v1') {
        const provenance = (value as any)?.provenance
        if (
          !SHA256.test(provenance?.referenceScopeSha256) ||
          !['age_gender_region', 'age_gender', 'age', 'all'].includes(
            provenance?.referenceScopeDimensions
          ) ||
          typeof provenance?.referenceScopeBroadened !== 'boolean'
        ) {
          throw new Error('sleep reference scope is invalid')
        }
      }
      if (policy.analysisId === 'brainstem.sleep-baseline/v2') {
        const result = value as any
        const provenance = result?.provenance
        const metrics = result?.metrics
        const table = result?.table
        const nights = metrics?.[0]?.value
        const conclusions = table?.rows?.map((row: unknown[]) => row?.[4])
        const descriptiveOnly = 'Descriptive only; reference reliability not established'
        const expectedConclusion =
          nights === 7
            ? ['Baseline only', descriptiveOnly]
            : nights === 8
              ? [
                  'One recent night only; sustained comparison unavailable',
                  descriptiveOnly
                ]
              : [
                  'Higher than your seven-night baseline on both recent nights',
                  'Lower than your seven-night baseline on both recent nights',
                  'No sustained change shown',
                  descriptiveOnly
                ]
        if (
          result.status !== 'complete' ||
          result.title !== 'My repeated-night sleep baseline' ||
          !Number.isInteger(nights) ||
          nights < 7 ||
          nights > 9 ||
          metrics?.map((item: any) => item.label).join('|') !==
            'Qualifying nights|Typical recording duration|Typical derived sleeping rate|Typical accepted interval share' ||
          table?.title !== 'Seven-night baseline and later-night differences' ||
          table?.rows?.length !== 2 ||
          table.rows[0][0] !== 'Recording duration' ||
          table.rows[1][0] !== 'Derived sleeping rate' ||
          !Array.isArray(conclusions) ||
          conclusions.some((item: string) => !expectedConclusion.includes(item)) ||
          (nights === 7 &&
            table.rows.some((row: unknown[]) => row[2] !== null || row[3] !== null)) ||
          (nights === 8 &&
            table.rows.some((row: unknown[]) => row[2] === null || row[3] !== null)) ||
          (nights === 9 &&
            table.rows.some((row: unknown[]) => row[2] === null || row[3] === null)) ||
          !SHA256.test(provenance?.referenceScopeSha256) ||
          !['age_gender_region', 'age_gender', 'age', 'all'].includes(
            provenance?.referenceScopeDimensions
          ) ||
          typeof provenance?.referenceScopeBroadened !== 'boolean'
        ) {
          throw new Error('sleep baseline v2 result is invalid')
        }
      }
    } catch {
      throw new PersonalInsightError('personal_insight_result_invalid')
    }
    return
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
