import axios from 'axios'
import { createHash } from 'crypto'
import { getAddress, verifyMessage } from 'ethers'
import type { Signer } from 'ethers'
import type {
  DBComputeJob,
  ParticipantValueCommitment,
  PrivateDatasetPolicy
} from '../../@types/C2D/C2D.js'
import {
  assertPrivateDatasetConfiguration,
  privateDatasetHttpsAgent,
  PrivateDatasetError
} from './privateDataset.js'

const HEX_64 = /^[0-9a-f]{64}$/
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/
const SIGNATURE = /^0x[0-9a-fA-F]{130}$/
const RECEIPT_SCHEMA = 'brainstem.compute-receipt/v1'
const COMMITMENT_SCHEMA = 'brainstem.participant-value-commitment/v1'
const RESULT_SCHEMA = 'brainstem.c2d-result/v1'
const VALUE_POLICY = 'brainstem.equal-cohort-contribution/v1'
const MAX_RESPONSE_BYTES = 16 * 1024

export class ParticipantValueError extends Error {
  constructor(code: string) {
    super(code)
    this.name = 'ParticipantValueError'
  }
}

export interface ComputeReceipt {
  schema: typeof RECEIPT_SCHEMA
  jobIdHash: string
  inputSha256: string
  resultSha256: string
  resultSchema: typeof RESULT_SCHEMA
  resultStatus: 'complete' | 'insufficient_data'
  algorithmImageDigest: string
  completedAt: string
}

export function canonicalJson(value: object): string {
  const fields = value as Record<string, unknown>
  const ordered = Object.fromEntries(
    Object.keys(fields)
      .sort()
      .map((key) => [key, fields[key]])
  )
  return JSON.stringify(ordered)
}

function exactKeys(value: unknown, keys: string[]): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join('\0') === [...keys].sort().join('\0')
  )
}

function validTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const parsed = new Date(value)
  if (!Number.isFinite(parsed.getTime())) return false
  const canonical = parsed.toISOString()
  return value === canonical || value === canonical.replace('.000Z', 'Z')
}

export function createComputeReceipt(
  job: DBComputeJob,
  result: Buffer,
  policy: PrivateDatasetPolicy,
  completedAt: string = new Date().toISOString()
): ComputeReceipt {
  const jobIdHash = String(job.jobIdHash ?? '').replace(/^0x/, '')
  const inputSha256 = job.privateInputChecksum
  const algorithmImageDigest = policy.approvedAlgorithmImage.split('@').at(-1)
  const resultStatus = job.resultValidation?.status
  if (
    !HEX_64.test(jobIdHash) ||
    !HEX_64.test(inputSha256 ?? '') ||
    !IMAGE_DIGEST.test(algorithmImageDigest ?? '') ||
    !['complete', 'insufficient_data'].includes(resultStatus ?? '') ||
    job.resultValidation?.contract !== RESULT_SCHEMA ||
    !job.resultValidation.billable ||
    !validTimestamp(completedAt)
  ) {
    throw new ParticipantValueError('participant_value_receipt_invalid')
  }
  return {
    schema: RECEIPT_SCHEMA,
    jobIdHash,
    inputSha256,
    resultSha256: createHash('sha256').update(result).digest('hex'),
    resultSchema: RESULT_SCHEMA,
    resultStatus: resultStatus as ComputeReceipt['resultStatus'],
    algorithmImageDigest,
    completedAt
  }
}

export function validateParticipantValueCommitment(
  value: unknown,
  receipt: ComputeReceipt,
  crabSignerAddress: string
): ParticipantValueCommitment {
  const keys = [
    'schema',
    'computeReceiptSha256',
    'valuePolicy',
    'participantCount',
    'amountPerParticipant',
    'entitlementSetSha256',
    'committedAt',
    'signature'
  ]
  if (!exactKeys(value, keys)) {
    throw new ParticipantValueError('participant_value_commitment_invalid')
  }
  const receiptSha256 = createHash('sha256').update(canonicalJson(receipt)).digest('hex')
  if (
    value.schema !== COMMITMENT_SCHEMA ||
    value.computeReceiptSha256 !== receiptSha256 ||
    value.valuePolicy !== VALUE_POLICY ||
    !Number.isSafeInteger(value.participantCount) ||
    Number(value.participantCount) < 1 ||
    Number(value.participantCount) > 1_000 ||
    !Number.isSafeInteger(value.amountPerParticipant) ||
    Number(value.amountPerParticipant) < 1 ||
    Number(value.amountPerParticipant) > 1_000 ||
    typeof value.entitlementSetSha256 !== 'string' ||
    !HEX_64.test(value.entitlementSetSha256) ||
    !validTimestamp(value.committedAt) ||
    typeof value.signature !== 'string' ||
    !SIGNATURE.test(value.signature)
  ) {
    throw new ParticipantValueError('participant_value_commitment_invalid')
  }
  const unsigned: Record<string, unknown> = { ...value }
  delete unsigned.signature
  try {
    if (
      getAddress(verifyMessage(canonicalJson(unsigned), value.signature)) !==
      getAddress(crabSignerAddress)
    ) {
      throw new Error('wrong signer')
    }
  } catch {
    throw new ParticipantValueError('participant_value_signature_invalid')
  }
  return value as unknown as ParticipantValueCommitment
}

export async function commitParticipantValue(
  job: DBComputeJob,
  result: Buffer,
  policy: PrivateDatasetPolicy,
  signer: Signer,
  environment: NodeJS.ProcessEnv = process.env,
  attempts: number = 3
): Promise<ParticipantValueCommitment> {
  if (!policy.participantValue) {
    throw new ParticipantValueError('participant_value_not_configured')
  }
  try {
    assertPrivateDatasetConfiguration(policy, environment)
  } catch (error) {
    if (error instanceof PrivateDatasetError) {
      throw new ParticipantValueError(error.message)
    }
    throw error
  }
  const receipt = createComputeReceipt(job, result, policy)
  const signature = await signer.signMessage(canonicalJson(receipt))
  const url = new URL('/api/v1/internal/c2d/value-commit', policy.url).toString()
  let lastError: unknown
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await axios.post(
        url,
        { receipt, signature },
        {
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
            Authorization: `Bearer ${environment[policy.bearerTokenEnv]}`
          },
          httpsAgent: privateDatasetHttpsAgent(policy),
          timeout: 10_000,
          maxRedirects: 0,
          maxContentLength: MAX_RESPONSE_BYTES,
          maxBodyLength: MAX_RESPONSE_BYTES,
          validateStatus: (status) => status === 200
        }
      )
      if (!exactKeys(response.data, ['commitment'])) {
        throw new ParticipantValueError('participant_value_response_invalid')
      }
      return validateParticipantValueCommitment(
        response.data.commitment,
        receipt,
        policy.participantValue.crabSignerAddress
      )
    } catch (error) {
      lastError = error
      const status = axios.isAxiosError(error) ? error.response?.status : undefined
      if (
        error instanceof ParticipantValueError ||
        (status !== undefined && status < 500) ||
        attempt === attempts
      ) {
        break
      }
      await new Promise((resolve) => setTimeout(resolve, 100 * attempt))
    }
  }
  if (lastError instanceof ParticipantValueError) throw lastError
  throw new ParticipantValueError('participant_value_commit_failed')
}
