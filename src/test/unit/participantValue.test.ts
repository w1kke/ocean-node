import { expect } from 'chai'
import { createHash } from 'crypto'
import { createServer, type Server } from 'http'
import type { AddressInfo } from 'net'
import { Wallet, verifyMessage } from 'ethers'
import type { DBComputeJob, PrivateDatasetPolicy } from '../../@types/C2D/C2D.js'
import {
  canonicalJson,
  commitParticipantValue,
  createComputeReceipt,
  ParticipantValueError,
  prepareParticipantValue,
  validateParticipantValueCommitment
} from '../../components/c2d/participantValue.js'

const NODE = new Wallet(`0x${'11'.repeat(32)}`)
const CRAB = new Wallet(`0x${'22'.repeat(32)}`)
const OTHER = new Wallet(`0x${'33'.repeat(32)}`)
const RESULT = Buffer.from('{"schema":"brainstem.c2d-result/v1","status":"complete"}')

function job(status: 'complete' | 'insufficient_data' = 'complete'): DBComputeJob {
  return {
    jobIdHash: `0x${'a'.repeat(64)}`,
    privateInputChecksum: 'b'.repeat(64),
    resultValidation: {
      contract: 'brainstem.c2d-result/v1',
      status,
      billable: true
    }
  } as DBComputeJob
}

function policy(url: string): PrivateDatasetPolicy {
  return {
    url: `${url}/api/v1/internal/c2d/rr-cohort`,
    maxBytes: 1024,
    approvedAlgorithmImage: `brainstem/private-rr@sha256:${'c'.repeat(64)}`,
    bearerTokenEnv: 'CRAB_C2D_TEST_TOKEN',
    releaseId: 'd'.repeat(64),
    participantValue: { crabSignerAddress: CRAB.address }
  }
}

async function commitment(receipt: ReturnType<typeof createComputeReceipt>) {
  const unsigned = {
    schema: 'brainstem.participant-value-commitment/v1' as const,
    computeReceiptSha256: createHash('sha256')
      .update(canonicalJson(receipt))
      .digest('hex'),
    valuePolicy: 'brainstem.equal-cohort-contribution/v1' as const,
    participantCount: receipt.resultStatus === 'insufficient_data' ? null : 20,
    amountPerParticipant: 3,
    entitlementSetSha256: 'e'.repeat(64),
    committedAt: receipt.completedAt
  }
  return { ...unsigned, signature: await CRAB.signMessage(canonicalJson(unsigned)) }
}

describe('participant value receipt handshake', () => {
  let server: Server
  let baseUrl: string
  let requests: number
  let failOnce: boolean
  let receivedAuthorization: string
  let receivedBody: any

  beforeEach(async () => {
    requests = 0
    failOnce = false
    receivedAuthorization = ''
    receivedBody = null
    server = createServer((request, response) => {
      requests += 1
      receivedAuthorization = String(request.headers.authorization ?? '')
      const chunks: Buffer[] = []
      request.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
      request.on('end', async () => {
        receivedBody = JSON.parse(Buffer.concat(chunks).toString())
        if (failOnce) {
          failOnce = false
          response.writeHead(503)
          response.end()
          return
        }
        const value = await commitment(receivedBody.receipt)
        response.writeHead(200, { 'Content-Type': 'application/json' })
        response.end(JSON.stringify({ commitment: value }))
      })
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address() as AddressInfo
    baseUrl = `http://127.0.0.1:${address.port}`
  })

  afterEach(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    )
  })

  it('signs the bounded receipt, retries a transient failure, and verifies Crab', async () => {
    failOnce = true
    const request = await prepareParticipantValue(job(), RESULT, policy(baseUrl), NODE)
    const result = await commitParticipantValue(request, policy(baseUrl), {
      CRAB_C2D_TEST_TOKEN: 'generated-test-token-that-is-long-enough'
    })

    expect(requests).to.equal(2)
    expect(receivedAuthorization).to.equal(
      'Bearer generated-test-token-that-is-long-enough'
    )
    expect(receivedBody.receipt).to.deep.include({
      schema: 'brainstem.compute-receipt/v1',
      jobIdHash: 'a'.repeat(64),
      inputSha256: 'b'.repeat(64),
      resultSha256: createHash('sha256').update(RESULT).digest('hex'),
      resultStatus: 'complete',
      algorithmImageDigest: `sha256:${'c'.repeat(64)}`
    })
    expect(
      verifyMessage(canonicalJson(receivedBody.receipt), receivedBody.signature)
    ).to.equal(NODE.address)
    expect(result.commitment).to.deep.include({
      participantCount: 20,
      amountPerParticipant: 3
    })
    expect(result.receipt).to.deep.equal(receivedBody.receipt)
    expect(result.receiptSignature).to.equal(receivedBody.signature)
  })

  it('reuses an exact persisted signed receipt across a restart', async () => {
    const computeJob = job()
    const first = await prepareParticipantValue(computeJob, RESULT, policy(baseUrl), NODE)
    computeJob.participantValueRequest = first

    expect(
      await prepareParticipantValue(computeJob, RESULT, policy(baseUrl), NODE)
    ).to.deep.equal(first)
    let error: unknown
    try {
      await prepareParticipantValue(
        computeJob,
        Buffer.from(`${RESULT.toString()} `),
        policy(baseUrl),
        NODE
      )
    } catch (caught) {
      error = caught
    }
    expect(error).to.be.instanceOf(ParticipantValueError)
    expect((error as Error).message).to.equal('participant_value_request_invalid')
  })

  it('accepts disclosure-safe suppression and rejects tampering or a wrong signer', async () => {
    const receipt = createComputeReceipt(
      job('insufficient_data'),
      RESULT,
      policy(baseUrl),
      '2026-07-25T00:00:00.000Z'
    )
    expect(receipt.resultStatus).to.equal('insufficient_data')
    const value = await commitment(receipt)
    expect(
      validateParticipantValueCommitment(value, receipt, CRAB.address)
    ).to.deep.equal(value)
    expect(value.participantCount).to.equal(null)

    expect(() =>
      validateParticipantValueCommitment(
        { ...value, amountPerParticipant: 4 },
        receipt,
        CRAB.address
      )
    ).to.throw(ParticipantValueError, 'participant_value_signature_invalid')
    expect(() =>
      validateParticipantValueCommitment(value, receipt, OTHER.address)
    ).to.throw(ParticipantValueError, 'participant_value_signature_invalid')
  })

  it('marks exhausted service failures retryable and explicit rejection terminal', async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    )
    server = createServer((request, response) => {
      requests += 1
      request.resume()
      response.writeHead(requests <= 2 ? 503 : 409)
      response.end()
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
    const request = await prepareParticipantValue(job(), RESULT, policy(baseUrl), NODE)

    let transient: ParticipantValueError | undefined
    try {
      await commitParticipantValue(
        request,
        policy(baseUrl),
        { CRAB_C2D_TEST_TOKEN: 'generated-test-token-that-is-long-enough' },
        2
      )
    } catch (error) {
      transient = error as ParticipantValueError
    }
    expect(transient.message).to.equal('participant_value_commit_unavailable')
    expect(transient.retryable).to.equal(true)

    let rejected: ParticipantValueError | undefined
    try {
      await commitParticipantValue(request, policy(baseUrl), {
        CRAB_C2D_TEST_TOKEN: 'generated-test-token-that-is-long-enough'
      })
    } catch (error) {
      rejected = error as ParticipantValueError
    }
    expect(rejected.message).to.equal('participant_value_commit_rejected')
    expect(rejected.retryable).to.equal(false)
  })
})
