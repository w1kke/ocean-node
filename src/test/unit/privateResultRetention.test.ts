/* eslint-disable security/detect-non-literal-fs-filename */
import { expect } from 'chai'
import sinon from 'sinon'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'fs'
import os from 'os'
import path from 'path'
import { createHash } from 'crypto'

import type { DBComputeJob, PrivateDatasetPolicy } from '../../@types/C2D/C2D.js'
import {
  C2DEngineDocker,
  PRIVATE_RESULT_RETENTION_SECONDS
} from '../../components/c2d/compute_engine_docker.js'
import { C2DDatabase, isStorageExpired } from '../../components/database/C2DDatabase.js'

const JOB_ID = '1'.repeat(64)
const OWNER = '0x0000000000000000000000000000000000000001'
const VIEWER = '0x0000000000000000000000000000000000000002'
const ALGORITHM_DIGEST = `sha256:${'a'.repeat(64)}`
const RESULT = Buffer.from('{"schema":"brainstem.c2d-result/v1","status":"complete"}')

function makeJob(finishedAt: number): DBComputeJob {
  return {
    jobId: JOB_ID,
    jobIdHash: `0x${createHash('sha256').update(JOB_ID).digest('hex')}`,
    owner: OWNER,
    additionalViewers: [VIEWER],
    environment: 'private-env',
    dateCreated: String(finishedAt - 30),
    dateFinished: String(finishedAt),
    status: 70,
    statusText: 'Job settled',
    results: [],
    did: 'did:ope:private',
    inputDID: ['did:ope:private-input'],
    algoDID: 'did:ope:private-algorithm',
    agreementId: '0xprivate-agreement',
    maxJobDuration: 60,
    clusterHash: 'test-cluster',
    configlogURL: 'private-config.log',
    publishlogURL: 'private-publish.log',
    algologURL: 'private-algorithm.log',
    outputsURL: 'private-output',
    stopRequested: false,
    algorithm: { documentId: 'did:ope:private-algorithm' },
    assets: [{ documentId: 'did:ope:private-input', userdata: { private: true } }],
    isRunning: false,
    isStarted: true,
    containerImage: `brainstem/private-rr@${ALGORITHM_DIGEST}`,
    isFree: false,
    algoStartTimestamp: String(finishedAt - 20),
    algoStopTimestamp: String(finishedAt - 1),
    resources: [{ id: 'cpu', amount: 1, price: 0.01 }],
    resultValidation: {
      contract: 'brainstem.c2d-result/v1',
      status: 'complete',
      billable: true
    },
    metadata: { private: true },
    terminationDetails: { exitCode: 0, OOMKilled: false },
    algoDuration: 19,
    queueMaxWaitTime: 0,
    encryptedDockerRegistryAuth: 'private-registry-auth',
    output: 'private-output-config',
    privateInputChecksum: 'b'.repeat(64),
    buildStartTimestamp: '0',
    buildStopTimestamp: '0'
  } as DBComputeJob
}

function makeEngine(tempFolder: string, db: any): C2DEngineDocker {
  const engine = new C2DEngineDocker(
    {
      type: 2,
      hash: 'test-cluster',
      tempFolder: `${tempFolder}/`,
      connection: {}
    } as any,
    db,
    {} as any,
    {} as any,
    {} as any
  )
  const notFound = () => Object.assign(new Error('not found'), { statusCode: 404 })
  engine.docker = {
    getContainer: () => {
      throw notFound()
    },
    getVolume: () => {
      throw notFound()
    }
  } as any
  const policy: PrivateDatasetPolicy = {
    url: 'http://crab:8080/api/v1/internal/c2d/rr-cohort',
    maxBytes: 1024,
    approvedAlgorithmImage: `brainstem/private-rr@${ALGORITHM_DIGEST}`,
    bearerTokenEnv: 'CRAB_C2D_BEARER_TOKEN',
    releaseId: 'c'.repeat(64)
  }
  ;(engine as any).privateDatasetPolicies.set('private-env', policy)
  return engine
}

function seedPrivateJobDirectory(engine: C2DEngineDocker): string {
  const root = path.join(engine.getStoragePath(), JOB_ID)
  for (const relative of [
    'data/inputs',
    'data/transformations',
    'data/ddos',
    'data/outputs',
    'data/logs',
    'tarData'
  ]) {
    mkdirSync(path.join(root, relative), { recursive: true })
  }
  writeFileSync(path.join(root, 'data/inputs/dataset.json'), 'private input')
  writeFileSync(path.join(root, 'data/ddos/dataset.json'), 'private ddo')
  writeFileSync(path.join(root, 'data/logs/algorithm.log'), 'private log')
  writeFileSync(path.join(root, 'tarData/upload.tar.gz'), 'private archive')
  writeFileSync(path.join(root, 'data/outputs/result.json'), RESULT)
  return root
}

async function streamText(stream: NodeJS.ReadableStream): Promise<string> {
  let text = ''
  for await (const chunk of stream) text += chunk.toString()
  return text
}

describe('private aggregate result retention', () => {
  let tempFolder: string

  beforeEach(() => {
    tempFolder = mkdtempSync(path.join(os.tmpdir(), 'private-result-retention-'))
  })

  afterEach(() => {
    sinon.restore()
    rmSync(tempFolder, { recursive: true, force: true })
  })

  it('retains only the validated aggregate and a sanitized wallet authorization row', async () => {
    const finishedAt = Math.floor(Date.now() / 1000)
    const job = makeJob(finishedAt)
    const db = {
      updateJob: sinon.stub().resolves(1),
      getJob: sinon.stub().callsFake(() => [job]),
      getSettlementByJobId: sinon.stub().resolves(null)
    }
    const engine = makeEngine(tempFolder, db)
    const originalRoot = seedPrivateJobDirectory(engine)

    expect(await (engine as any).cleanupPrivateJobMaterial(job)).to.equal(true)

    const retainedPath = (engine as any).getRetainedPrivateResultPath(job)
    expect(existsSync(originalRoot)).to.equal(false)
    expect(readFileSync(retainedPath).equals(RESULT)).to.equal(true)
    expect(job.privateResultRetention).to.deep.include({
      cleanupState: 'complete',
      inputChecksum: 'b'.repeat(64),
      algorithmImageDigest: ALGORITHM_DIGEST,
      expiresAt: finishedAt + PRIVATE_RESULT_RETENTION_SECONDS
    })
    expect(job.privateResultRetention?.resultChecksum).to.equal(
      createHash('sha256').update(RESULT).digest('hex')
    )
    expect(job).to.include({ owner: OWNER, environment: 'private-env' })
    expect(job.additionalViewers).to.deep.equal([VIEWER])
    expect(job.assets).to.deep.equal([])
    expect(job.algorithm).to.deep.equal({})
    expect(job).not.to.have.property('did')
    expect(job).not.to.have.property('inputDID')
    expect(job).not.to.have.property('algoDID')
    expect(job).not.to.have.property('agreementId')
    expect(job).not.to.have.property('metadata')
    expect(job).not.to.have.property('terminationDetails')
    expect(job).not.to.have.property('encryptedDockerRegistryAuth')
    expect(job).not.to.have.property('output')
    expect(job).not.to.have.property('privateInputChecksum')

    const ownerResult = await engine.getComputeJobResult(OWNER, JOB_ID, 0)
    expect(await streamText(ownerResult.stream)).to.equal(RESULT.toString())
    const viewerResult = await engine.getComputeJobResult(VIEWER, JOB_ID, 0)
    expect(await streamText(viewerResult.stream)).to.equal(RESULT.toString())
    let denied: Error = null
    try {
      await engine.getComputeJobResult(
        '0x0000000000000000000000000000000000000003',
        JOB_ID,
        0
      )
    } catch (error) {
      denied = error as Error
    }
    expect(denied?.message).to.include('not authorized')
  })

  it('retains only the allowlisted Insight presentation metadata', async () => {
    const finishedAt = Math.floor(Date.now() / 1000)
    const job = makeJob(finishedAt)
    const insightId = `did:ope:${'d'.repeat(64)}`
    job.metadata = {
      purpose: 'brainstem-insights-local-proof',
      insightId,
      resultSchema: 'brainstem.c2d-result/v1',
      privateNote: 'must not survive'
    }
    const db = {
      updateJob: sinon.stub().resolves(1),
      getJob: sinon.stub().callsFake(() => [job]),
      getSettlementByJobId: sinon.stub().resolves(null)
    }
    const engine = makeEngine(tempFolder, db)
    seedPrivateJobDirectory(engine)

    expect(await (engine as any).cleanupPrivateJobMaterial(job)).to.equal(true)
    expect(job.metadata).to.deep.equal({
      purpose: 'brainstem-insights-local-proof',
      insightId,
      resultSchema: 'brainstem.c2d-result/v1'
    })

    const [status] = await engine.getComputeJobStatus(OWNER, null, JOB_ID)
    expect(status.metadata).to.deep.equal(job.metadata)
    expect(status.results).to.deep.equal([
      {
        filename: 'result.json',
        filesize: RESULT.length,
        type: 'output',
        index: 0
      }
    ])
  })

  it('withholds a value-enabled result until the verified commitment is persisted', async () => {
    const finishedAt = Math.floor(Date.now() / 1000)
    const job = makeJob(finishedAt)
    const db = {
      updateJob: sinon.stub().resolves(1),
      getJob: sinon.stub().callsFake(() => [job]),
      getSettlementByJobId: sinon.stub().resolves(null)
    }
    const engine = makeEngine(tempFolder, db)
    const configured = (engine as any).privateDatasetPolicies.get('private-env')
    configured.participantValue = {
      crabSignerAddress: '0x1111111111111111111111111111111111111111'
    }
    job.participantValueRequired = true
    seedPrivateJobDirectory(engine)
    expect(await (engine as any).cleanupPrivateJobMaterial(job)).to.equal(true)

    expect(
      (await engine.getComputeJobStatus(OWNER, null, JOB_ID))[0].results
    ).to.deep.equal([])
    job.participantValue = {
      schema: 'brainstem.participant-value-commitment/v1',
      computeReceiptSha256: 'c'.repeat(64),
      valuePolicy: 'brainstem.equal-cohort-contribution/v1',
      participantCount: 20,
      amountPerParticipant: 3,
      entitlementSetSha256: 'd'.repeat(64),
      committedAt: '2026-07-25T00:00:00Z',
      signature: `0x${'e'.repeat(130)}`
    }
    const [status] = await engine.getComputeJobStatus(OWNER, null, JOB_ID)
    expect(status.results).to.have.length(1)
    expect(status.participantValue).to.deep.equal(job.participantValue)
  })

  it('stops serving at the exact expiry boundary and deletes disk plus database idempotently', async () => {
    const now = Math.floor(Date.now() / 1000)
    const job = makeJob(now)
    let deleted = false
    const db = {
      updateJob: sinon.stub().resolves(1),
      deleteJob: sinon.stub().callsFake(() => {
        deleted = true
        return true
      }),
      getJob: sinon.stub().callsFake(() => (deleted ? [] : [job])),
      getSettlementByJobId: sinon.stub().resolves(null)
    }
    const engine = makeEngine(tempFolder, db)
    seedPrivateJobDirectory(engine)
    expect(await (engine as any).cleanupPrivateJobMaterial(job)).to.equal(true)

    job.privateResultRetention!.expiresAt = now + 1
    const beforeExpiry = await engine.getComputeJobResult(OWNER, JOB_ID, 0)
    expect(await streamText(beforeExpiry.stream)).to.equal(RESULT.toString())
    job.privateResultRetention!.expiresAt = now
    expect(await engine.getComputeJobResult(OWNER, JOB_ID, 0)).to.equal(null)

    expect(await engine.cleanupExpiredStorage(job)).to.equal(true)
    expect(job.additionalViewers).to.deep.equal([])
    expect(existsSync((engine as any).getRetainedPrivateResultDirectory(job))).to.equal(
      false
    )
    expect(await engine.cleanupExpiredStorage(job)).to.equal(true)
  })

  it('uses inclusive retention boundaries and never DB-deletes an orphan without its storage engine', async () => {
    const now = Math.floor(Date.now() / 1000)
    const job = makeJob(now - PRIVATE_RESULT_RETENTION_SECONDS)
    job.privateResultRetention = {
      cleanupState: 'complete',
      algorithmImageDigest: ALGORITHM_DIGEST,
      expiresAt: now
    }
    expect(isStorageExpired(job, 1, now - 1)).to.equal(false)
    expect(isStorageExpired(job, 1, now)).to.equal(true)

    const database = Object.create(C2DDatabase.prototype) as C2DDatabase
    const provider = {
      getFinishedJobs: sinon.stub().resolves([job]),
      deleteJob: sinon.stub().resolves(true)
    }
    ;(database as any).provider = provider
    expect(await database.cleanOrphanJobs([], [])).to.equal(0)
    expect(provider.deleteJob.notCalled).to.equal(true)

    const cleanup = sinon.stub().resolves(true)
    const engine = {
      getC2DConfig: () => ({ hash: job.clusterHash }),
      cleanupExpiredStorage: cleanup
    }
    expect(await database.cleanOrphanJobs([], [engine])).to.equal(1)
    expect(cleanup.calledOnceWith(job)).to.equal(true)
    expect(provider.deleteJob.notCalled).to.equal(true)
  })

  it('deletes an expired result but keeps the sanitized row until payment is settled', async () => {
    const job = makeJob(Math.floor(Date.now() / 1000))
    job.payment = {
      chainId: 11155420,
      token: '0x0000000000000000000000000000000000000004',
      lockTx: '0xlock',
      claimTx: '',
      cancelTx: '',
      cost: 0.25
    }
    let settlementStatus = 'prepared'
    let deleted = false
    const db = {
      updateJob: sinon.stub().resolves(1),
      deleteJob: sinon.stub().callsFake(() => {
        deleted = true
        return true
      }),
      getJob: sinon.stub().callsFake(() => (deleted ? [] : [job])),
      getSettlementByJobId: sinon.stub().callsFake(() => ({
        status: settlementStatus
      }))
    }
    const engine = makeEngine(tempFolder, db)
    seedPrivateJobDirectory(engine)
    expect(await (engine as any).cleanupPrivateJobMaterial(job)).to.equal(true)

    expect(await engine.cleanupExpiredStorage(job)).to.equal(false)
    expect(deleted).to.equal(false)
    expect(job.privateResultRetention?.resultDeletedAt).to.be.a('number')
    expect(existsSync((engine as any).getRetainedPrivateResultPath(job))).to.equal(false)

    settlementStatus = 'charged'
    expect(await engine.cleanupExpiredStorage(job)).to.equal(true)
    expect(deleted).to.equal(true)
  })

  it('does not mark deletion complete while a private Docker volume may still exist', async () => {
    const job = makeJob(Math.floor(Date.now() / 1000))
    let deleted = false
    const db = {
      updateJob: sinon.stub().resolves(1),
      getJob: sinon.stub().callsFake(() => (deleted ? [] : [job])),
      deleteJob: sinon.stub().callsFake(() => {
        deleted = true
        return true
      }),
      getSettlementByJobId: sinon.stub().resolves(null)
    }
    const engine = makeEngine(tempFolder, db)
    const originalRoot = seedPrivateJobDirectory(engine)
    const notFound = Object.assign(new Error('not found'), { statusCode: 404 })
    engine.docker = {
      getContainer: () => {
        throw notFound
      },
      getVolume: () => ({
        remove: sinon.stub().rejects(new Error('volume busy'))
      })
    } as any

    expect(await (engine as any).cleanupJob(job)).to.equal(false)
    expect(job.privateResultRetention?.cleanupState).to.equal('failed')
    expect(existsSync(originalRoot)).to.equal(false)
    expect(existsSync((engine as any).getRetainedPrivateResultPath(job))).to.equal(true)

    expect(await engine.cleanupExpiredStorage(job)).to.equal(false)
    expect(job.privateResultRetention?.resultDeletedAt).to.be.a('number')
    expect(existsSync((engine as any).getRetainedPrivateResultPath(job))).to.equal(false)

    engine.docker = {
      getContainer: () => {
        throw notFound
      },
      getVolume: () => {
        throw notFound
      }
    } as any
    expect(await engine.cleanupExpiredStorage(job)).to.equal(true)
    expect(job.privateResultRetention?.cleanupState).to.equal('complete')
    expect(deleted).to.equal(true)
  })

  it('keeps a failed cleanup observable and repairs it on restart', async () => {
    const job = makeJob(Math.floor(Date.now() / 1000))
    const db = {
      updateJob: sinon.stub().resolves(1),
      getFinishedJobs: sinon.stub().resolves([job])
    }
    const engine = makeEngine(tempFolder, db)
    const originalRoot = seedPrivateJobDirectory(engine)
    const retainedDirectory = (engine as any).getRetainedPrivateResultDirectory(job)
    mkdirSync(retainedDirectory, { recursive: true })
    writeFileSync(path.join(retainedDirectory, 'result.json'), 'corrupt')
    job.privateResultRetention = {
      cleanupState: 'pending',
      inputChecksum: 'b'.repeat(64),
      resultChecksum: createHash('sha256').update(RESULT).digest('hex'),
      algorithmImageDigest: ALGORITHM_DIGEST,
      expiresAt: Math.floor(Date.now() / 1000) + PRIVATE_RESULT_RETENTION_SECONDS
    }

    expect(await (engine as any).cleanupPrivateJobMaterial(job)).to.equal(false)
    expect(job.privateResultRetention.cleanupState).to.equal('failed')
    expect(job.privateResultRetention.cleanupErrorCode).to.equal('private_cleanup_failed')
    expect(existsSync(originalRoot)).to.equal(true)

    rmSync(retainedDirectory, { recursive: true, force: true })
    await (engine as any).recoverPrivateJobMaterial()
    expect(job.privateResultRetention.cleanupState).to.equal('complete')
    expect(existsSync(originalRoot)).to.equal(false)
  })
})
