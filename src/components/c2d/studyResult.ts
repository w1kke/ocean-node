import axios from 'axios'
import { createHash } from 'crypto'
import { renameSync, rmSync, writeFileSync } from 'fs'
import type { DBComputeJob, PrivateDatasetPolicy } from '../../@types/C2D/C2D.js'
import {
  assertPrivateDatasetConfiguration,
  privateDatasetHttpsAgent,
  PrivateDatasetError
} from './privateDataset.js'
import { createComputeReceipt } from './participantValue.js'

const MAX_RESULT_BYTES = 256 * 1024
const MAX_BODY_BYTES = 320 * 1024

export class StudyResultCommitError extends Error {
  constructor(
    code: string,
    readonly retryable: boolean = false
  ) {
    super(code)
    this.name = 'StudyResultCommitError'
  }
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.keys(value as Record<string, unknown>)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`
      )
      .join(',')}}`
  }
  return JSON.stringify(value)
}

export async function commitStudyResult(
  job: DBComputeJob,
  resultBytes: Buffer,
  policy: PrivateDatasetPolicy,
  resultPath: string,
  environment: NodeJS.ProcessEnv = process.env,
  attempts: number = 3
): Promise<void> {
  if (!policy.study || !job.privateSourceSnapshotSha256) {
    throw new StudyResultCommitError('study_result_not_configured')
  }
  try {
    assertPrivateDatasetConfiguration(policy, environment)
  } catch (error) {
    if (error instanceof PrivateDatasetError) {
      throw new StudyResultCommitError(error.message)
    }
    throw error
  }
  let result: Record<string, unknown>
  if (resultBytes.length > MAX_RESULT_BYTES) {
    throw new StudyResultCommitError('study_result_invalid')
  }
  try {
    result = JSON.parse(resultBytes.toString('utf8'))
  } catch {
    throw new StudyResultCommitError('study_result_invalid')
  }
  const provenance = result.provenance as Record<string, unknown>
  const generatedAt = provenance?.generatedAt
  if (
    typeof generatedAt !== 'string' ||
    provenance.datasetSchemaVersion !== 'brainstem.full-night-rr-cohort/v1' ||
    job.resultValidation?.datasetSchemaVersion !== 'brainstem.full-night-rr-cohort/v1'
  ) {
    throw new StudyResultCommitError('study_result_invalid')
  }
  const temporaryResultPath = `${resultPath}.tmp`
  try {
    writeFileSync(temporaryResultPath, resultBytes, { mode: 0o600 })
    renameSync(temporaryResultPath, resultPath)
  } catch {
    throw new StudyResultCommitError('study_result_stage_failed')
  } finally {
    rmSync(temporaryResultPath, { force: true })
  }
  const receipt = createComputeReceipt(job, resultBytes, policy, generatedAt)
  const body = {
    schema: 'brainstem.study-result-commit/v1',
    revisionId: policy.study.revisionId,
    revisionSha256: policy.study.revisionSha256,
    jobIdHash: receipt.jobIdHash,
    inputSha256: receipt.inputSha256,
    sourceSnapshotSha256: job.privateSourceSnapshotSha256,
    algorithmImageDigest: receipt.algorithmImageDigest,
    completedAt: receipt.completedAt,
    result
  }
  const expectedResultSha256 = createHash('sha256')
    .update(canonical(result))
    .digest('hex')
  const url = new URL(
    `/api/v1/internal/study-proposals/${policy.study.proposalId}/results`,
    policy.url
  ).toString()
  let lastError: unknown
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await axios.post(url, body, {
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          Authorization: `Bearer ${environment[policy.study.resultBearerTokenEnv]}`
        },
        httpsAgent: privateDatasetHttpsAgent(policy),
        timeout: 10_000,
        maxRedirects: 0,
        maxContentLength: MAX_BODY_BYTES,
        maxBodyLength: MAX_BODY_BYTES,
        validateStatus: (status) => status === 201
      })
      const stored = response.data?.result
      if (
        !stored ||
        stored.proposalId !== policy.study.proposalId ||
        stored.revisionId !== policy.study.revisionId ||
        stored.revisionSha256 !== policy.study.revisionSha256 ||
        stored.resultSha256 !== expectedResultSha256 ||
        stored.algorithmImageDigest !== receipt.algorithmImageDigest
      ) {
        throw new StudyResultCommitError('study_result_response_invalid')
      }
      return
    } catch (error) {
      lastError = error
      const status = axios.isAxiosError(error) ? error.response?.status : undefined
      if (
        error instanceof StudyResultCommitError ||
        (status !== undefined && status < 500) ||
        attempt === attempts
      ) {
        break
      }
      await new Promise((resolve) => setTimeout(resolve, 100 * attempt))
    }
  }
  if (lastError instanceof StudyResultCommitError) throw lastError
  const status = axios.isAxiosError(lastError) ? lastError.response?.status : undefined
  const retryable =
    status === undefined || status >= 500 || [408, 425, 429].includes(status)
  throw new StudyResultCommitError(
    retryable ? 'study_result_commit_unavailable' : 'study_result_commit_rejected',
    retryable
  )
}
