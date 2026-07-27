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
  policy: PrivateDatasetPolicy,
  environment: NodeJS.ProcessEnv = process.env
): void {
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
  policy: PrivateDatasetPolicy
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
    'X-Brainstem-Cohort-Release-Id': policy.releaseId
  }
}

function requiredHeader(value: unknown, pattern: RegExp, code: string): string {
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw new PrivateDatasetError(code)
  }
  return value
}

export function downloadPrivateDataset(
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
  return downloadVerifiedJson(
    policy.url,
    destination,
    policy.maxBytes,
    requestHeaders(file, jobId, policy, environment),
    privateDatasetHttpsAgent(policy)
  )
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
