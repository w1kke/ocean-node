/* eslint-disable require-await */
import { expect } from 'chai'
import sinon from 'sinon'
import os from 'os'
import path from 'path'
import { mkdtempSync, rmSync } from 'fs'

import {
  C2DStatusNumber,
  C2DStatusText,
  type DBComputeJob,
  type DBSettlementIntent,
  type DBSettlementStatus
} from '../../@types/C2D/C2D.js'

const TOKEN = '0x2222222222222222222222222222222222222222'
const PAYER = '0x3333333333333333333333333333333333333333'
const PAYEE = '0x4444444444444444444444444444444444444444'
const ESCROW = '0x5555555555555555555555555555555555555555'
const TX = `0x${'a'.repeat(64)}`

function paidJob(status = C2DStatusNumber.JobSettle): DBComputeJob {
  return {
    jobId: 'settlement-job',
    jobIdHash: '1',
    owner: PAYER,
    environment: 'private-env',
    status,
    statusText: C2DStatusText.JobSettle,
    isFree: false,
    stopRequested: false,
    payment: {
      chainId: 1,
      token: TOKEN,
      lockTx: `0x${'b'.repeat(64)}`,
      claimTx: '',
      cancelTx: '',
      cost: 0
    },
    resultValidation: {
      contract: 'brainstem.c2d-result/v1',
      status: 'complete',
      billable: true
    },
    resources: [{ id: 'cpu', amount: 1 }],
    algoStartTimestamp: '1',
    algoStopTimestamp: '2',
    buildStartTimestamp: '0',
    buildStopTimestamp: '0',
    maxJobDuration: 60,
    queueMaxWaitTime: 0,
    dateCreated: '1',
    dateFinished: '2',
    results: []
  } as DBComputeJob
}

async function makeWorker(job: DBComputeJob) {
  if (!process.env.PRIVATE_KEY) process.env.PRIVATE_KEY = `0x${'11'.repeat(32)}`
  const { C2DEngineDocker } =
    await import('../../components/c2d/compute_engine_docker.js')
  const records = new Map<string, DBSettlementIntent>()
  let failBroadcastUpdate = false
  const db = {
    getJobsByStatus: sinon
      .stub()
      .callsFake(async () => (job.status === C2DStatusNumber.JobFinished ? [] : [job])),
    updateJob: sinon.stub().resolves(1),
    getSettlementByKey: sinon
      .stub()
      .callsFake(async (key: string) => records.get(key) ?? null),
    getSettlementByJobId: sinon
      .stub()
      .callsFake(async (jobId: string) =>
        [...records.values()].find((record) => record.jobId === jobId)
      ),
    insertSettlementIntent: sinon.stub().callsFake(async (intent: DBSettlementIntent) => {
      if ([...records.values()].some((record) => record.jobId === intent.jobId)) {
        return false
      }
      records.set(intent.settlementKey, { ...intent })
      return true
    }),
    updateSettlementStatus: sinon
      .stub()
      .callsFake(
        async (
          key: string,
          status: DBSettlementStatus,
          transactionHash?: string,
          receiptBlock?: number,
          settledAmount?: number
        ) => {
          if (status === 'broadcast' && failBroadcastUpdate) {
            failBroadcastUpdate = false
            throw new Error('simulated database failure after broadcast')
          }
          const record = records.get(key)
          if (!record) return false
          record.status = status
          if (transactionHash) record.transactionHash = transactionHash
          if (receiptBlock !== undefined) record.receiptBlock = receiptBlock
          if (settledAmount !== undefined) record.settledAmount = settledAmount
          return true
        }
      )
  } as any
  const tempFolder = mkdtempSync(path.join(os.tmpdir(), 'settlement-worker-')) + '/'
  const engine = new C2DEngineDocker(
    {
      type: 2,
      hash: 'settlement-test',
      tempFolder,
      connection: { paymentClaimInterval: null }
    } as any,
    db,
    {} as any,
    {} as any,
    {} as any
  )
  ;(engine as any).envs = [
    {
      id: job.environment,
      minJobDuration: 0,
      fees: {
        1: [{ feeToken: TOKEN, prices: [{ id: 'cpu', price: 0.25 }] }]
      }
    }
  ]
  sinon.stub(engine, 'getComputeEnvironment').resolves((engine as any).envs[0])
  ;(engine as any).privateDatasetPolicies.set(job.environment, {})
  ;(engine as any).cleanUpUnknownLocks = sinon.stub().resolves()
  engine.keyManager = { getEthAddress: () => PAYEE } as any

  let locks: any[] = [
    {
      jobId: job.jobIdHash,
      expiry: String(Math.floor(Date.now() / 1000) + 300),
      token: TOKEN,
      payer: PAYER
    }
  ]
  let receipt = { confirmed: false, success: false } as {
    confirmed: boolean
    success: boolean
    blockNumber?: number
  }
  let event: any = null
  const escrow = {
    getLocks: sinon.stub().callsFake(async () => locks),
    getEscrowContractAddressForChain: sinon.stub().returns(ESCROW),
    getCurrentBlockNumber: sinon.stub().resolves(100),
    getSettlementTransactionReceipt: sinon.stub().callsFake(async () => receipt),
    findSettlementEvent: sinon.stub().callsFake(async () => event),
    prepareClaimLock: sinon.stub().resolves({
      transactionHash: TX,
      rawTransaction: '0x1234'
    }),
    prepareCancelExpiredLock: sinon.stub().resolves({
      transactionHash: TX,
      rawTransaction: '0x1234'
    }),
    broadcastSettlementTransaction: sinon.stub().resolves(TX)
  }
  engine.escrow = escrow as any

  return {
    engine,
    db,
    escrow,
    records,
    tempFolder,
    setLocks: (value: any[]) => {
      locks = value
    },
    setReceipt: (value: typeof receipt) => {
      receipt = value
    },
    setEvent: (value: any) => {
      event = value
    },
    failNextBroadcastUpdate: () => {
      failBroadcastUpdate = true
    }
  }
}

describe('paid settlement worker', () => {
  const folders: string[] = []

  afterEach(() => {
    sinon.restore()
    for (const folder of folders.splice(0)) {
      rmSync(folder, { recursive: true, force: true })
    }
  })

  it('serializes concurrent cron entry and exposes a charge only after confirmation', async () => {
    const worker = await makeWorker(paidJob())
    folders.push(worker.tempFolder)
    let releaseClaim: (value: string) => void
    worker.escrow.broadcastSettlementTransaction.callsFake(
      () =>
        new Promise<string>((resolve) => {
          releaseClaim = resolve
        })
    )

    const first = (worker.engine as any).claimPayments()
    await new Promise((resolve) => setImmediate(resolve))
    const overlapping = (worker.engine as any).claimPayments()
    await overlapping
    releaseClaim!(TX)
    await first

    expect(worker.escrow.broadcastSettlementTransaction.calledOnce).to.equal(true)
    expect([...worker.records.values()][0].status).to.equal('broadcast')
    expect([...worker.records.values()][0].decision).to.equal('charge')
    expect([...worker.records.values()][0].amount).to.equal(0.25)
    expect(worker.db.updateJob.notCalled).to.equal(true)

    worker.setLocks([])
    worker.setReceipt({ confirmed: true, success: true, blockNumber: 101 })
    worker.setEvent({
      decision: 'charge',
      mutation: 'claim',
      amount: 0.25,
      transactionHash: TX,
      blockNumber: 101
    })
    await (worker.engine as any).claimPayments()

    expect(worker.escrow.broadcastSettlementTransaction.calledOnce).to.equal(true)
    expect([...worker.records.values()][0].status).to.equal('charged')
    expect(worker.db.updateJob.calledOnce).to.equal(true)
  })

  it('rebroadcasts the same signed transaction after a database failure', async () => {
    const job = paidJob()
    const worker = await makeWorker(job)
    folders.push(worker.tempFolder)
    worker.failNextBroadcastUpdate()

    await (worker.engine as any).claimPayments()
    expect(worker.escrow.broadcastSettlementTransaction.calledOnce).to.equal(true)
    expect([...worker.records.values()][0].status).to.equal('prepared')

    await (worker.engine as any).claimPayments()
    expect(worker.escrow.prepareClaimLock.calledOnce).to.equal(true)
    expect(worker.escrow.broadcastSettlementTransaction.calledTwice).to.equal(true)
    expect(worker.escrow.broadcastSettlementTransaction.firstCall.args).to.deep.equal(
      worker.escrow.broadcastSettlementTransaction.secondCall.args
    )
    expect([...worker.records.values()][0].status).to.equal('broadcast')

    worker.setLocks([])
    worker.setEvent({
      decision: 'charge',
      mutation: 'claim',
      amount: 0.25,
      transactionHash: TX,
      blockNumber: 101
    })
    await (worker.engine as any).claimPayments()

    expect(worker.escrow.broadcastSettlementTransaction.calledTwice).to.equal(true)
    expect([...worker.records.values()][0].status).to.equal('charged')
    expect(job.status).to.equal(C2DStatusNumber.JobFinished)
  })

  it('keeps an unexplained missing lock unknown instead of inventing nolock', async () => {
    const job = paidJob()
    const worker = await makeWorker(job)
    folders.push(worker.tempFolder)
    worker.setLocks([])
    worker.setReceipt({ confirmed: true, success: true, blockNumber: 90 })

    await (worker.engine as any).claimPayments()

    expect(worker.escrow.broadcastSettlementTransaction.notCalled).to.equal(true)
    expect([...worker.records.values()][0].status).to.equal('unknown')
    expect(job.status).to.equal(C2DStatusNumber.JobSettle)
  })

  it('excludes terminal free failures from settlement reconciliation', async () => {
    const job = paidJob(C2DStatusNumber.ResultsFetchFailed)
    job.isFree = true
    delete job.payment
    const worker = await makeWorker(job)
    folders.push(worker.tempFolder)
    const finish = sinon.spy(worker.engine as any, 'finishJobWithoutPayment')

    await (worker.engine as any).claimPayments()

    expect(job.status).to.equal(C2DStatusNumber.ResultsFetchFailed)
    expect(finish.notCalled).to.equal(true)
    expect(worker.db.updateJob.notCalled).to.equal(true)
  })

  it('claims zero for technical failures and cancels expired locks', async () => {
    const failed = paidJob(C2DStatusNumber.ImageScanFailed)
    delete failed.resultValidation
    const zeroWorker = await makeWorker(failed)
    folders.push(zeroWorker.tempFolder)
    await (zeroWorker.engine as any).claimPayments()
    expect(zeroWorker.escrow.prepareClaimLock.calledOnce).to.equal(true)
    expect(zeroWorker.escrow.prepareClaimLock.firstCall.args[4]).to.equal(0)

    const expiredJob = paidJob()
    const expiredWorker = await makeWorker(expiredJob)
    folders.push(expiredWorker.tempFolder)
    expiredWorker.setLocks([
      {
        jobId: expiredJob.jobIdHash,
        expiry: String(Math.floor(Date.now() / 1000) - 1),
        token: TOKEN,
        payer: PAYER
      }
    ])
    await (expiredWorker.engine as any).claimPayments()
    expect(expiredWorker.escrow.prepareCancelExpiredLock.calledOnce).to.equal(true)
    expect(expiredWorker.escrow.prepareClaimLock.notCalled).to.equal(true)

    expiredWorker.setLocks([])
    expiredWorker.setReceipt({ confirmed: true, success: true, blockNumber: 102 })
    expiredWorker.setEvent({
      decision: 'release',
      mutation: 'cancel',
      amount: 0.5,
      transactionHash: TX,
      blockNumber: 102
    })
    await (expiredWorker.engine as any).claimPayments()
    const refunded = [...expiredWorker.records.values()][0]
    expect(refunded.status).to.equal('refunded')
    expect(refunded.settledAmount).to.equal(0.5)
    expect(expiredJob.payment.cancelTx).to.equal(TX)
  })
})
