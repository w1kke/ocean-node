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
type PrivateTransportPolicy = Omit<PrivateDatasetPolicy, 'analysisId' | 'paperInsight'> &
  Partial<Pick<PrivateDatasetPolicy, 'analysisId' | 'paperInsight'>>

export class PrivateDatasetError extends Error {
  constructor(code: string) {
    super(code)
    this.name = 'PrivateDatasetError'
  }
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
    if (
      !dataset ||
      Array.isArray(dataset) ||
      Object.keys(dataset).sort().join(',') !== 'participants,schema' ||
      dataset.schema !== policy.paperInsight.inputSchema ||
      !Array.isArray(dataset.participants) ||
      dataset.participants.length > 1000
    ) {
      throw new Error('invalid dataset')
    }
    const subjects = new Set<string>()
    for (const participant of dataset.participants) {
      if (
        !participant ||
        Array.isArray(participant) ||
        Object.keys(participant).sort().join(',') !== 'recordings,subjectId' ||
        typeof participant.subjectId !== 'string' ||
        !SHA256.test(participant.subjectId) ||
        subjects.has(participant.subjectId) ||
        !Array.isArray(participant.recordings) ||
        participant.recordings.length < 1 ||
        participant.recordings.length > 16
      ) {
        throw new Error('invalid participant')
      }
      subjects.add(participant.subjectId)
      for (const recording of participant.recordings) {
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
          recording.rrIntervalsMs.length < 180 ||
          recording.rrIntervalsMs.length > 3600 ||
          recording.rrIntervalsMs.some(
            (value: unknown) =>
              typeof value !== 'number' ||
              !Number.isFinite(value) ||
              value < 250 ||
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
