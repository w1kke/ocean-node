import { expect } from 'chai'
import {
  C2DStatusNumber,
  type DBComputeJob,
  type DBSettlementIntent
} from '../../@types/C2D/C2D.js'
import {
  decideSettlement,
  projectSettlement,
  sameSettlementIntent,
  SETTLEMENT_JOB_STATUSES
} from '../../components/c2d/settlement.js'

function job(status: C2DStatusNumber): DBComputeJob {
  return {
    status,
    stopRequested: false
  } as DBComputeJob
}

function intent(overrides: Partial<DBSettlementIntent> = {}): DBSettlementIntent {
  return {
    settlementKey: 'key',
    jobId: 'job',
    jobIdHash: '1',
    chainId: 1,
    escrowAddress: '0x1111111111111111111111111111111111111111',
    token: '0x2222222222222222222222222222222222222222',
    payer: '0x3333333333333333333333333333333333333333',
    decision: 'charge',
    amount: 0.25,
    reason: 'validated_result',
    preparedBlock: 100,
    status: 'prepared',
    createdAt: 1,
    updatedAt: 1,
    ...overrides
  }
}

describe('paid compute settlement policy', () => {
  it('releases every terminal technical failure with zero charge', () => {
    for (const status of SETTLEMENT_JOB_STATUSES.filter(
      (candidate) => candidate !== C2DStatusNumber.JobSettle
    )) {
      expect(decideSettlement(job(status), 0.25, true)).to.deep.equal({
        decision: 'release',
        amount: 0,
        reason: `technical_failure:${status}`
      })
    }
  })

  it('charges only validated complete or privacy-suppressed private results', () => {
    const complete = job(C2DStatusNumber.JobSettle)
    complete.resultValidation = {
      contract: 'brainstem.c2d-result/v1',
      status: 'complete',
      billable: true
    }
    expect(decideSettlement(complete, 0.25, true)).to.deep.equal({
      decision: 'charge',
      amount: 0.25,
      reason: 'validated_result'
    })

    complete.resultValidation.status = 'insufficient_data'
    expect(decideSettlement(complete, 0.25, true).reason).to.equal(
      'validated_privacy_suppression'
    )
    complete.resultValidation = {
      contract: 'brainstem.c2d-result/v1',
      status: 'failed',
      billable: false
    }
    expect(decideSettlement(complete, 0.25, true)).to.deep.equal({
      decision: 'release',
      amount: 0,
      reason: 'result_status:failed'
    })
    delete complete.resultValidation
    expect(decideSettlement(complete, 0.25, true).reason).to.equal(
      'result_contract_missing'
    )
  })

  it('names the paid cancellation policy after execution', () => {
    const stopped = job(C2DStatusNumber.JobSettle)
    stopped.stopRequested = true
    stopped.resultValidation = {
      contract: 'brainstem.c2d-result/v1',
      status: 'complete',
      billable: true
    }
    expect(decideSettlement(stopped, 0.25, true).reason).to.equal(
      'validated_result_after_consumer_stop'
    )
  })

  it('keeps intent decisions immutable and exposes only confirmed facts', () => {
    const prepared = intent()
    expect(sameSettlementIntent(prepared, { ...prepared, status: 'broadcast' })).to.equal(
      true
    )
    expect(sameSettlementIntent(prepared, { ...prepared, amount: 0.5 })).to.equal(false)
    expect(projectSettlement(prepared)).to.deep.equal({ status: 'unknown', amount: 0 })
    expect(
      projectSettlement({
        ...prepared,
        status: 'charged',
        transactionHash: `0x${'a'.repeat(64)}`
      })
    ).to.deep.equal({
      status: 'charged',
      amount: 0.25,
      chainId: 1,
      token: prepared.token,
      transactionHash: `0x${'a'.repeat(64)}`
    })
    expect(
      projectSettlement({
        ...prepared,
        status: 'refunded',
        amount: 0,
        settledAmount: 0.5,
        transactionHash: `0x${'b'.repeat(64)}`
      })
    ).to.deep.equal({
      status: 'refunded',
      amount: 0.5,
      chainId: 1,
      token: prepared.token,
      transactionHash: `0x${'b'.repeat(64)}`
    })
  })
})
