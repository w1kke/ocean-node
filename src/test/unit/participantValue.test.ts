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
    participantCount: 20,
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
    const result = await commitParticipantValue(job(), RESULT, policy(baseUrl), NODE, {
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
    expect(result).to.deep.include({
      participantCount: 20,
      amountPerParticipant: 3
    })
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
})
