/* eslint-disable security/detect-non-literal-fs-filename */
import axios from 'axios'
import { createHash, timingSafeEqual } from 'crypto'
import {
  createWriteStream,
  existsSync,
  lstatSync,
  readFileSync,
  renameSync,
  rmSync
} from 'fs'
import { Agent as HttpsAgent } from 'https'
import { Readable, Transform } from 'stream'
import { pipeline } from 'stream/promises'
import type { PrivateDatasetPolicy } from '../../@types/C2D/C2D.js'
import type { UrlFileObject } from '../../@types/fileObject.js'

const JOB_ID = /^[0-9a-f]{64}$/
const SHA256 = /^[0-9a-f]{64}$/
const JOB_HEADER = 'x-ocean-compute-job-id'
const RELEASE_HEADER = 'x-brainstem-cohort-release-id'
const ANALYSIS_HEADER = 'x-brainstem-analysis-id'
const METHODS_CANDIDATE_SHA256 =
  '15dbf8544c87d81c06f5e512b00e9fe39dd6431dd1a4079a97da68a3f92721c1'
const SAMPLE_ENTROPY_CANDIDATE_SHA256 =
  '65002ab13f02f812c611085c0295b81dc90ec7ffacc79f9ff4927e81e9070bdd'
const OVERNIGHT_CHANGE_CANDIDATE_SHA256 =
  '56e996b4cde15689b7524e7e9427b7fc67dd722d77493fd1daac67d421d90907'
const MOVEMENT_SCHEMA = 'brainstem.normalized-movement/v1'
const MOVEMENT_THRESHOLD_MILLIG = 100
const REST_REPEATABILITY_CANDIDATE_SHA256 =
  '09e22348e350bb9e1da7183929675f7d67e718eb183075a7735c5513468905dd'
const STANDING_RESPONSE_CANDIDATE_SHA256 =
  'ee503af519ed241f1f7ec965b58ad41b38c622c71a43e3f44c86743722ac4217'
const GUIDED_BREATHING_CANDIDATE_SHA256 =
  'e64490c6539db744350ee761db4a1fedffd6f9f631f8814480a684c1fdc4931d'
type PrivateTransportPolicy = Omit<PrivateDatasetPolicy, 'analysisId' | 'paperInsight'> &
  Partial<Pick<PrivateDatasetPolicy, 'analysisId' | 'paperInsight'>>

export class PrivateDatasetError extends Error {
  constructor(code: string) {
    super(code)
    this.name = 'PrivateDatasetError'
  }
}

function isGuidedBreathingProtocol(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const protocol = value as Record<string, unknown>
  return (
    Object.keys(protocol).sort().join(',') === 'eh,ep,ih,ip,rateCPM' &&
    protocol.rateCPM === 6 &&
    protocol.ih === 5 &&
    protocol.ip === 0 &&
    protocol.eh === 5 &&
    protocol.ep === 0
  )
}

export function assertPrivateDatasetJob(
  policy: PrivateDatasetPolicy,
  image: string,
  assetCount: number,
  hasRemoteOutput: boolean = false
): void {
  if (image !== policy.approvedAlgorithmImage) {
    throw new PrivateDatasetError('private_dataset_algorithm_not_approved')
  }
  if (assetCount !== 1) {
    throw new PrivateDatasetError('private_dataset_requires_one_asset')
  }
  if (hasRemoteOutput) {
    throw new PrivateDatasetError('private_dataset_remote_output_not_allowed')
  }
}

export function assertPrivateDatasetConfiguration(
  policy: PrivateTransportPolicy,
  environment: NodeJS.ProcessEnv = process.env
): void {
  if (
    policy.analysisId === 'brainstem.resting-rr-cohort-summary/v1' &&
    policy.paperInsight !== undefined
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.resting-hrv-methods/v1' &&
    (policy.paperInsight?.algorithmVersion !== '0.1.0' ||
      policy.paperInsight.inputSchema !== 'brainstem.resting-hrv-methods-cohort/v1' ||
      policy.paperInsight.candidateManifestSha256 !== METHODS_CANDIDATE_SHA256 ||
      !SHA256.test(policy.paperInsight.approvedManifestSha256) ||
      !SHA256.test(policy.paperInsight.referenceSha256) ||
      policy.paperInsight.evidenceTier !== 'E2_brainstem_compatible_exploratory' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited')
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.resting-rr-sample-entropy/v1' &&
    (policy.paperInsight?.algorithmVersion !== '0.1.0' ||
      policy.paperInsight.inputSchema !== 'brainstem.resting-sample-entropy-cohort/v1' ||
      policy.paperInsight.candidateManifestSha256 !== SAMPLE_ENTROPY_CANDIDATE_SHA256 ||
      !SHA256.test(policy.paperInsight.approvedManifestSha256) ||
      !SHA256.test(policy.paperInsight.referenceSha256) ||
      policy.paperInsight.evidenceTier !== 'E2_brainstem_compatible_exploratory' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited')
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.overnight-heart-rate-change/v1' &&
    (policy.paperInsight?.algorithmVersion !== '0.2.0' ||
      policy.paperInsight.inputSchema !==
        'brainstem.overnight-heart-rate-change-cohort/v2' ||
      policy.paperInsight.candidateManifestSha256 !== OVERNIGHT_CHANGE_CANDIDATE_SHA256 ||
      !SHA256.test(policy.paperInsight.approvedManifestSha256) ||
      policy.paperInsight.referenceSha256 !== null ||
      policy.paperInsight.evidenceTier !== 'E1_public_reproduced' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited')
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.resting-hrv-repeatability/v1' &&
    (policy.paperInsight?.algorithmVersion !== '0.1.0' ||
      policy.paperInsight.inputSchema !==
        'brainstem.resting-hrv-repeatability-cohort/v1' ||
      policy.paperInsight.candidateManifestSha256 !==
        REST_REPEATABILITY_CANDIDATE_SHA256 ||
      !SHA256.test(policy.paperInsight.approvedManifestSha256) ||
      policy.paperInsight.referenceSha256 !== null ||
      policy.paperInsight.evidenceTier !== 'E0_candidate' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited')
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.standing-heart-rate-response/v1' &&
    (policy.paperInsight?.algorithmVersion !== '0.1.0' ||
      policy.paperInsight.inputSchema !==
        'brainstem.standing-heart-rate-response-cohort/v1' ||
      policy.paperInsight.candidateManifestSha256 !==
        STANDING_RESPONSE_CANDIDATE_SHA256 ||
      !SHA256.test(policy.paperInsight.approvedManifestSha256) ||
      policy.paperInsight.referenceSha256 !== null ||
      policy.paperInsight.evidenceTier !== 'E2_brainstem_compatible_exploratory' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited')
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.guided-breathing-response/v1' &&
    (policy.paperInsight?.algorithmVersion !== '0.1.0' ||
      policy.paperInsight.inputSchema !==
        'brainstem.guided-breathing-response-cohort/v1' ||
      policy.paperInsight.candidateManifestSha256 !== GUIDED_BREATHING_CANDIDATE_SHA256 ||
      !SHA256.test(policy.paperInsight.approvedManifestSha256) ||
      policy.paperInsight.referenceSha256 !== null ||
      policy.paperInsight.evidenceTier !== 'E2_brainstem_compatible_exploratory' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited')
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  const bearerToken = environment[policy.bearerTokenEnv]
  if (
    typeof bearerToken !== 'string' ||
    bearerToken.length < 32 ||
    bearerToken.includes('\n') ||
    bearerToken.includes('\r')
  ) {
    throw new PrivateDatasetError('private_dataset_credential_invalid')
  }
  if (!policy.tls) return

  const url = new URL(policy.url)
  if (
    url.protocol !== 'https:' ||
    url.hostname.toLowerCase() !== policy.tls.serverName.toLowerCase()
  ) {
    throw new PrivateDatasetError('private_dataset_tls_identity_invalid')
  }
  for (const [file, privateFile] of [
    [policy.tls.caFile, false],
    [policy.tls.clientCertificateFile, false],
    [policy.tls.clientKeyFile, true]
  ] as Array<[string, boolean]>) {
    try {
      const fileStat = lstatSync(file)
      if (
        fileStat.isSymbolicLink() ||
        !fileStat.isFile() ||
        fileStat.size < 1 ||
        fileStat.size > 64 * 1024 ||
        (privateFile ? (fileStat.mode & 0o077) !== 0 : (fileStat.mode & 0o022) !== 0)
      ) {
        throw new Error('unsafe TLS file')
      }
      readFileSync(file)
    } catch (_error) {
      throw new PrivateDatasetError('private_dataset_tls_file_invalid')
    }
  }
}

export function privateDatasetHttpsAgent(
  policy: PrivateTransportPolicy
): HttpsAgent | undefined {
  if (!policy.tls) return undefined
  return new HttpsAgent({
    ca: readFileSync(policy.tls.caFile),
    cert: readFileSync(policy.tls.clientCertificateFile),
    key: readFileSync(policy.tls.clientKeyFile),
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
    keepAlive: false,
    maxSockets: 1
  })
}

function requestHeaders(
  file: UrlFileObject,
  jobId: string,
  policy: PrivateDatasetPolicy,
  environment: NodeJS.ProcessEnv
): Record<string, string> {
  const suppliedHeaders = Object.entries(file.headers ?? {})
  for (const [key] of suppliedHeaders) {
    if (key.toLowerCase() === JOB_HEADER) {
      throw new PrivateDatasetError('private_dataset_job_header_is_reserved')
    }
    if (key.toLowerCase() === RELEASE_HEADER) {
      throw new PrivateDatasetError('private_dataset_release_header_is_reserved')
    }
    if (key.toLowerCase() === ANALYSIS_HEADER) {
      throw new PrivateDatasetError('private_dataset_analysis_header_is_reserved')
    }
  }
  if (suppliedHeaders.length > 0) {
    throw new PrivateDatasetError('private_dataset_headers_not_allowed')
  }
  assertPrivateDatasetConfiguration(policy, environment)
  return {
    Accept: 'application/json',
    'Accept-Encoding': 'identity',
    Authorization: `Bearer ${environment[policy.bearerTokenEnv]}`,
    'X-Ocean-Compute-Job-Id': jobId,
    'X-Brainstem-Cohort-Release-Id': policy.releaseId,
    'X-Brainstem-Analysis-Id': policy.analysisId
  }
}

function requiredHeader(value: unknown, pattern: RegExp, code: string): string {
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw new PrivateDatasetError(code)
  }
  return value
}

function validateReviewedCohortInput(
  destination: string,
  policy: PrivateDatasetPolicy
): void {
  if (!policy.paperInsight) return
  try {
    const dataset = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(destination))
    )
    const overnight =
      policy.paperInsight.inputSchema ===
      'brainstem.overnight-heart-rate-change-cohort/v2'
    const repeatability =
      policy.paperInsight.inputSchema === 'brainstem.resting-hrv-repeatability-cohort/v1'
    const standing =
      policy.paperInsight.inputSchema ===
      'brainstem.standing-heart-rate-response-cohort/v1'
    const guidedBreathing =
      policy.paperInsight.inputSchema === 'brainstem.guided-breathing-response-cohort/v1'
    if (
      !dataset ||
      Array.isArray(dataset) ||
      Object.keys(dataset).sort().join(',') !==
        (guidedBreathing
          ? 'allowedUse,participants,policy,protocol,schema,sourceType'
          : overnight
            ? 'allowedUse,movementSchema,movementThresholdMilliG,participants,policy,schema,sourceType'
            : repeatability || standing
              ? 'allowedUse,participants,policy,schema,sourceType'
              : 'participants,schema') ||
      dataset.schema !== policy.paperInsight.inputSchema ||
      ((overnight || repeatability || standing || guidedBreathing) &&
        dataset.sourceType !== 'approved_real_cohort') ||
      (overnight &&
        (dataset.policy !==
          'brainstem.overnight-heart-rate-change-cohort/distinct-9-movement/v2' ||
          dataset.allowedUse !== 'aggregate_overnight_change_only' ||
          dataset.movementSchema !== MOVEMENT_SCHEMA ||
          dataset.movementThresholdMilliG !== MOVEMENT_THRESHOLD_MILLIG)) ||
      (repeatability &&
        (dataset.policy !== 'brainstem.resting-hrv-repeatability-cohort/distinct-7/v1' ||
          dataset.allowedUse !== 'aggregate_resting_repeatability_only')) ||
      (standing &&
        (dataset.policy !== 'brainstem.standing-heart-rate-response-cohort/latest-7/v1' ||
          dataset.allowedUse !== 'aggregate_standing_response_only')) ||
      (guidedBreathing &&
        (dataset.policy !==
          'brainstem.guided-breathing-response-cohort/protocol-6-5-0-5-0/latest-7/v1' ||
          dataset.allowedUse !== 'aggregate_guided_breathing_response_only' ||
          !isGuidedBreathingProtocol(dataset.protocol))) ||
      !Array.isArray(dataset.participants) ||
      dataset.participants.length > 1000
    ) {
      throw new Error('invalid dataset')
    }
    const subjects = new Set<string>()
    const sampleEntropy =
      policy.paperInsight.inputSchema === 'brainstem.resting-sample-entropy-cohort/v1'
    for (const participant of dataset.participants) {
      const values = overnight ? participant?.nights : participant?.recordings
      if (
        !participant ||
        Array.isArray(participant) ||
        Object.keys(participant).sort().join(',') !==
          (overnight ? 'nights,subjectId' : 'recordings,subjectId') ||
        typeof participant.subjectId !== 'string' ||
        !SHA256.test(participant.subjectId) ||
        subjects.has(participant.subjectId) ||
        !Array.isArray(values) ||
        values.length < 1 ||
        values.length >
          (overnight
            ? 9
            : repeatability || standing || guidedBreathing
              ? 7
              : sampleEntropy
                ? 1
                : 16) ||
        ((overnight || repeatability) && values.length !== (overnight ? 9 : 7))
      ) {
        throw new Error('invalid participant')
      }
      subjects.add(participant.subjectId)
      if (overnight) {
        for (let index = 0; index < values.length; index += 1) {
          const night = values[index]
          if (
            !night ||
            Array.isArray(night) ||
            Object.keys(night).sort().join(',') !==
              'acceptedIntervalCount,alignedHeartRateSampleFraction,durationCoverageRatio,durationSeconds,intervalSumMs,movementCoverageFraction,movementEventCount,movementEventRatePerHour,movementMeanHeartRateBpm,nightIndex,normalToNormalProvenance,observedIntervalCount,officialMethodInputCompatible,quietMeanHeartRateBpm,quietWindowProportion' ||
            night.nightIndex !== index + 1 ||
            !Number.isInteger(night.durationSeconds) ||
            night.durationSeconds < 18_000 ||
            night.durationSeconds > 43_200 ||
            !Number.isInteger(night.observedIntervalCount) ||
            !Number.isInteger(night.acceptedIntervalCount) ||
            night.acceptedIntervalCount < 9_000 ||
            night.acceptedIntervalCount > night.observedIntervalCount ||
            night.acceptedIntervalCount / night.observedIntervalCount < 0.95 ||
            typeof night.intervalSumMs !== 'number' ||
            !Number.isFinite(night.intervalSumMs) ||
            typeof night.durationCoverageRatio !== 'number' ||
            !Number.isFinite(night.durationCoverageRatio) ||
            night.durationCoverageRatio < 0.9 ||
            night.durationCoverageRatio > 1.1 ||
            Math.abs(
              night.durationCoverageRatio -
                night.intervalSumMs / 1000 / night.durationSeconds
            ) > 0.000001 ||
            typeof night.movementCoverageFraction !== 'number' ||
            !Number.isFinite(night.movementCoverageFraction) ||
            night.movementCoverageFraction < 0.8 ||
            night.movementCoverageFraction > 1 ||
            typeof night.alignedHeartRateSampleFraction !== 'number' ||
            !Number.isFinite(night.alignedHeartRateSampleFraction) ||
            night.alignedHeartRateSampleFraction < 0.8 ||
            night.alignedHeartRateSampleFraction > 1 ||
            !Number.isInteger(night.movementEventCount) ||
            night.movementEventCount < 0 ||
            night.movementEventCount > night.durationSeconds ||
            typeof night.movementEventRatePerHour !== 'number' ||
            !Number.isFinite(night.movementEventRatePerHour) ||
            Math.abs(
              night.movementEventRatePerHour -
                night.movementEventCount / (night.durationSeconds / 3600)
            ) > 0.000001 ||
            typeof night.quietWindowProportion !== 'number' ||
            !Number.isFinite(night.quietWindowProportion) ||
            night.quietWindowProportion < 0 ||
            night.quietWindowProportion > 1 ||
            ![night.quietMeanHeartRateBpm, night.movementMeanHeartRateBpm].every(
              (value) =>
                value === null ||
                (typeof value === 'number' &&
                  Number.isFinite(value) &&
                  value >= 20 &&
                  value <= 250)
            ) ||
            (night.quietWindowProportion === 0) !==
              (night.quietMeanHeartRateBpm === null) ||
            (night.movementEventCount === 0) !==
              (night.movementMeanHeartRateBpm === null) ||
            night.normalToNormalProvenance !== 'unverified' ||
            night.officialMethodInputCompatible !== false
          ) {
            throw new Error('invalid night')
          }
        }
        continue
      }
      if (standing) {
        for (const recording of values) {
          const representedSeconds = Array.isArray(recording?.rrIntervalsMs)
            ? recording.rrIntervalsMs.reduce(
                (total: number, value: number) => total + value,
                0
              ) / 1000
            : Number.NaN
          if (
            !recording ||
            Array.isArray(recording) ||
            Object.keys(recording).sort().join(',') !==
              'durationSeconds,recordingType,rrIntervalsMs' ||
            recording.recordingType !== 'posture' ||
            !Number.isInteger(recording.durationSeconds) ||
            recording.durationSeconds < 295 ||
            recording.durationSeconds > 305 ||
            !Array.isArray(recording.rrIntervalsMs) ||
            recording.rrIntervalsMs.length < 148 ||
            recording.rrIntervalsMs.length > 1100 ||
            recording.rrIntervalsMs.some(
              (value: unknown) =>
                typeof value !== 'number' ||
                !Number.isFinite(value) ||
                value < 300 ||
                value > 2000
            ) ||
            representedSeconds < 295 ||
            representedSeconds > 305 ||
            Math.abs(representedSeconds - recording.durationSeconds) > 5
          ) {
            throw new Error('invalid recording')
          }
        }
        continue
      }
      if (guidedBreathing) {
        const indices = new Set<number>()
        for (const recording of values) {
          const coverage = Array.isArray(recording?.rrIntervalsMs)
            ? recording.rrIntervalsMs.reduce(
                (total: number, value: number) => total + value,
                0
              ) /
              1000 /
              recording.durationSeconds
            : Number.NaN
          if (
            !recording ||
            Array.isArray(recording) ||
            Object.keys(recording).sort().join(',') !==
              'durationSeconds,protocol,recordingIndex,recordingType,rrIntervalsMs' ||
            !Number.isInteger(recording.recordingIndex) ||
            recording.recordingIndex < 1 ||
            recording.recordingIndex > 7 ||
            indices.has(recording.recordingIndex) ||
            recording.recordingType !== 'exercise' ||
            !Number.isInteger(recording.durationSeconds) ||
            recording.durationSeconds < 120 ||
            recording.durationSeconds > 1800 ||
            !isGuidedBreathingProtocol(recording.protocol) ||
            !Array.isArray(recording.rrIntervalsMs) ||
            recording.rrIntervalsMs.length < 1 ||
            recording.rrIntervalsMs.length > 6000 ||
            recording.rrIntervalsMs.some(
              (value: unknown) =>
                typeof value !== 'number' ||
                !Number.isFinite(value) ||
                value < 300 ||
                value > 2000
            ) ||
            coverage < 0.9 ||
            coverage > 1.1
          ) {
            throw new Error('invalid recording')
          }
          indices.add(recording.recordingIndex)
        }
        continue
      }
      for (const recording of values) {
        if (
          !recording ||
          Array.isArray(recording) ||
          Object.keys(recording).sort().join(',') !==
            'durationSeconds,recordingType,rrIntervalsMs' ||
          recording.recordingType !== 'rest' ||
          !Number.isInteger(recording.durationSeconds) ||
          recording.durationSeconds < 300 ||
          recording.durationSeconds > 360 ||
          !Array.isArray(recording.rrIntervalsMs) ||
          recording.rrIntervalsMs.length < (sampleEntropy ? 240 : 180) ||
          recording.rrIntervalsMs.length > (sampleEntropy ? 900 : 3600) ||
          recording.rrIntervalsMs.some(
            (value: unknown) =>
              typeof value !== 'number' ||
              !Number.isFinite(value) ||
              value < (sampleEntropy ? 300 : 250) ||
              value > 2000
          ) ||
          Math.abs(
            recording.rrIntervalsMs.reduce(
              (total: number, value: number) => total + value,
              0
            ) /
              1000 -
              recording.durationSeconds
          ) > Math.max(5, recording.durationSeconds * 0.1)
        ) {
          throw new Error('invalid recording')
        }
      }
    }
  } catch {
    rmSync(destination, { force: true })
    throw new PrivateDatasetError('private_dataset_contract_invalid')
  }
}

export async function downloadPrivateDataset(
  file: UrlFileObject,
  destination: string,
  jobId: string,
  policy: PrivateDatasetPolicy,
  environment: NodeJS.ProcessEnv = process.env
): Promise<{ bytes: number; checksum: string }> {
  if (!JOB_ID.test(jobId)) {
    throw new PrivateDatasetError('private_dataset_job_id_invalid')
  }
  if (
    file.type !== 'url' ||
    file.method.toLowerCase() !== 'get' ||
    file.url !== policy.url
  ) {
    throw new PrivateDatasetError('private_dataset_url_not_allowed')
  }
  const result = await downloadVerifiedJson(
    policy.url,
    destination,
    policy.maxBytes,
    requestHeaders(file, jobId, policy, environment),
    privateDatasetHttpsAgent(policy)
  )
  validateReviewedCohortInput(destination, policy)
  return result
}

export async function downloadVerifiedJson(
  url: string,
  destination: string,
  maxBytes: number,
  headers: Record<string, string>,
  httpsAgent?: HttpsAgent
): Promise<{ bytes: number; checksum: string }> {
  const partial = `${destination}.part`
  let responseStream: Readable | undefined
  try {
    if (existsSync(destination)) {
      throw new PrivateDatasetError('private_dataset_destination_exists')
    }
    rmSync(partial, { force: true })

    const response = await axios({
      method: 'get',
      url,
      headers,
      httpsAgent,
      responseType: 'stream',
      timeout: 30000,
      maxRedirects: 0,
      decompress: false,
      validateStatus: (status) => status === 200
    })
    responseStream = response.data
    const contentType = String(response.headers['content-type'] ?? '')
      .split(';', 1)[0]
      .trim()
      .toLowerCase()
    if (contentType !== 'application/json') {
      throw new PrivateDatasetError('private_dataset_content_type_invalid')
    }
    const contentEncoding = response.headers['content-encoding']
    if (contentEncoding && String(contentEncoding).toLowerCase() !== 'identity') {
      throw new PrivateDatasetError('private_dataset_content_encoding_invalid')
    }
    const contentLengthText = requiredHeader(
      response.headers['content-length'],
      /^(0|[1-9][0-9]*)$/,
      'private_dataset_content_length_invalid'
    )
    const declaredBytes = Number(contentLengthText)
    if (!Number.isSafeInteger(declaredBytes) || declaredBytes > maxBytes) {
      throw new PrivateDatasetError('private_dataset_too_large')
    }
    const expectedChecksum = requiredHeader(
      response.headers['x-content-sha256'],
      SHA256,
      'private_dataset_checksum_invalid'
    )

    let bytes = 0
    const hash = createHash('sha256')
    const verifier = new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
        bytes += buffer.length
        if (bytes > maxBytes) {
          callback(new PrivateDatasetError('private_dataset_too_large'))
          return
        }
        hash.update(buffer)
        callback(null, buffer)
      }
    })
    await pipeline(
      responseStream,
      verifier,
      createWriteStream(partial, { flags: 'wx', mode: 0o600 })
    )
    if (bytes !== declaredBytes) {
      throw new PrivateDatasetError('private_dataset_length_mismatch')
    }
    const checksum = hash.digest('hex')
    if (
      !timingSafeEqual(Buffer.from(checksum, 'hex'), Buffer.from(expectedChecksum, 'hex'))
    ) {
      throw new PrivateDatasetError('private_dataset_checksum_mismatch')
    }
    renameSync(partial, destination)
    return { bytes, checksum }
  } catch (error) {
    responseStream?.destroy()
    rmSync(partial, { force: true })
    if (error instanceof PrivateDatasetError) throw error
    throw new PrivateDatasetError('private_dataset_fetch_failed')
  }
}
