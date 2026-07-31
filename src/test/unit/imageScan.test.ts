/* eslint-disable security/detect-non-literal-fs-filename */
import { expect } from 'chai'
import sinon from 'sinon'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs'
import os from 'os'
import path from 'path'
import { PassThrough, Readable } from 'stream'

import {
  C2DStatusNumber,
  C2DStatusText,
  type DBComputeJob,
  type ImageScanSeverity
} from '../../@types/C2D/C2D.js'
import { evaluateTrivyReport } from '../../components/c2d/imageScan.js'

const cleanReport: { SchemaVersion: number; Results: unknown[] } = {
  SchemaVersion: 2,
  Results: []
}
const findingsReport = {
  SchemaVersion: 2,
  Results: [
    {
      Vulnerabilities: [
        {
          Severity: 'HIGH',
          VulnerabilityID: 'CVE-HIGH',
          PkgName: 'high-package',
          Title: 'High finding'
        },
        {
          Severity: 'CRITICAL',
          VulnerabilityID: 'CVE-CRITICAL',
          PkgName: 'critical-package'
        }
      ]
    }
  ]
}

function ensureTestEnv() {
  if (!process.env.PRIVATE_KEY) process.env.PRIVATE_KEY = `0x${'11'.repeat(32)}`
}

async function makeEngine(options: {
  tempFolder: string
  scanImages: boolean
  severities?: ImageScanSeverity[]
  scanInterval?: number
}) {
  ensureTestEnv()
  const { C2DEngineDocker } =
    await import('../../components/c2d/compute_engine_docker.js')
  const db = {
    updateJob: sinon.stub().resolves(),
    getRunningJobs: sinon.stub().resolves([]),
    getJobsByStatus: sinon.stub().resolves([])
  } as any
  const cluster = {
    type: 2,
    hash: 'scan-test',
    tempFolder: options.tempFolder,
    connection: {
      scanImages: options.scanImages,
      scanImageRejectSeverities: options.severities,
      imageCleanupInterval: null,
      paymentClaimInterval: null,
      scanImageDBUpdateInterval: options.scanInterval ?? null
    }
  } as any
  const engine = new C2DEngineDocker(cluster, db, {} as any, {} as any, {} as any)
  ;(engine as any).cleanupJob = sinon.stub().resolves()
  return { engine, db }
}

function makeScannerContainer(output: string, statusCode = 0, stderr = false) {
  const logs = Readable.from([Buffer.from(output)])
  const remove = sinon.stub().resolves()
  return {
    start: sinon.stub().resolves(),
    wait: sinon.stub().resolves({ StatusCode: statusCode }),
    logs: sinon.stub().resolves(logs),
    remove,
    modem: {
      demuxStream: (
        _source: Readable,
        stdout: NodeJS.WritableStream,
        error: NodeJS.WritableStream
      ) => logs.pipe(stderr ? error : stdout)
    }
  } as any
}

function allowScannerRun(engine: any) {
  engine.checkscanDBImage = sinon.stub().resolves()
  engine.ensureFreshScanDatabase = sinon.stub().resolves()
  engine.sendImageToScanner = sinon.stub().resolves()
}

function makeJob(): DBComputeJob {
  return {
    jobId: 'job-scan',
    owner: '0x0000000000000000000000000000000000000001',
    environment: 'env-scan',
    containerImage: 'example/image@sha256:digest',
    status: C2DStatusNumber.ConfiguringVolumes,
    statusText: C2DStatusText.ConfiguringVolumes,
    isRunning: true,
    isStarted: false,
    isFree: true,
    stopRequested: false,
    dateCreated: String(Date.now() / 1000),
    dateFinished: '',
    maxJobDuration: 60,
    queueMaxWaitTime: 0,
    buildStartTimestamp: '0',
    buildStopTimestamp: '0',
    resources: [],
    results: [],
    algorithm: {},
    assets: [],
    clusterHash: 'scan-test',
    configlogURL: '',
    publishlogURL: '',
    algologURL: '',
    outputsURL: '',
    algoStartTimestamp: '0',
    algoStopTimestamp: '0',
    algoDuration: 0,
    jobIdHash: '1'
  } as DBComputeJob
}

async function rejectedMessage(action: Promise<unknown>): Promise<string> {
  try {
    await action
  } catch (error) {
    return (error as Error).message
  }
  return ''
}

describe('fail-closed image scanning', () => {
  let tempFolder: string

  beforeEach(() => {
    tempFolder = mkdtempSync(path.join(os.tmpdir(), 'ocean-image-scan-')) + '/'
  })

  afterEach(() => {
    sinon.restore()
    rmSync(tempFolder, { recursive: true, force: true })
  })

  it('uses the configured severity policy to evaluate a valid report', () => {
    expect(evaluateTrivyReport(findingsReport, ['CRITICAL']).vulnerable).to.equal(true)
    expect(evaluateTrivyReport(findingsReport, ['HIGH']).vulnerable).to.equal(true)
    expect(evaluateTrivyReport(findingsReport, ['MEDIUM']).vulnerable).to.equal(false)
    expect(evaluateTrivyReport(cleanReport, ['HIGH', 'CRITICAL']).summary.total).to.equal(
      0
    )
  })

  it('rejects malformed reports instead of treating them as clean', () => {
    for (const report of [
      null,
      {},
      { SchemaVersion: 2 },
      { SchemaVersion: null, Results: [] },
      { SchemaVersion: 2, Results: {} },
      { SchemaVersion: 2, Results: [{ Vulnerabilities: {} }] },
      {
        SchemaVersion: 2,
        Results: [{ Vulnerabilities: [{ Severity: 'HIGH', VulnerabilityID: 'CVE' }] }]
      }
    ]) {
      expect(() => evaluateTrivyReport(report, ['HIGH'])).to.throw()
    }
  })

  it('fails when the scanner image cannot be inspected or pulled', async () => {
    const { engine } = await makeEngine({
      tempFolder,
      scanImages: true,
      severities: ['HIGH']
    })
    ;(engine as any).docker = {
      getImage: () => ({
        inspect: sinon.stub().rejects({ statusCode: 500, message: 'down' })
      })
    }
    expect(await rejectedMessage((engine as any).checkscanDBImage())).to.include(
      'Unable to inspect'
    )
    ;(engine as any).docker = {
      getImage: () => ({ inspect: sinon.stub().rejects({ statusCode: 404 }) }),
      pull: sinon.stub().rejects(new Error('pull failed')),
      modem: { followProgress: sinon.stub() }
    }
    expect(await rejectedMessage((engine as any).checkscanDBImage())).to.include(
      'pull failed'
    )
  })

  it('streams the exported image over a hijacked scanner stdin', async () => {
    const { engine } = await makeEngine({
      tempFolder,
      scanImages: true,
      severities: ['HIGH']
    })
    const input = new PassThrough()
    const chunks: Buffer[] = []
    input.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
    const scanner = {
      attach: sinon.stub().resolves(input),
      start: sinon.stub().resolves()
    }
    ;(engine as any).docker = {
      getImage: () => ({ get: sinon.stub().resolves(Readable.from(['image'])) })
    }

    await (engine as any).sendImageToScanner(scanner, 'example/image')

    expect(scanner.attach.firstCall.args[0]).to.include({
      hijack: true,
      stdin: true
    })
    expect(scanner.start.calledOnce).to.equal(true)
    expect(Buffer.concat(chunks).toString()).to.equal('image')
  })

  it('uses one severity list for Trivy and evaluation and removes the scanner', async () => {
    const { engine } = await makeEngine({
      tempFolder,
      scanImages: true,
      severities: ['HIGH', 'CRITICAL']
    })
    const container = makeScannerContainer(JSON.stringify(findingsReport))
    const createContainer = sinon.stub().resolves(container)
    allowScannerRun(engine as any)
    ;(engine as any).docker = { createContainer }

    const result = await (engine as any).checkImageVulnerability('example/image')

    expect(result.vulnerable).to.equal(true)
    expect(createContainer.firstCall.args[0].Cmd[0]).to.include('HIGH,CRITICAL')
    expect(createContainer.firstCall.args[0].Cmd[0]).to.include('/scan/image.tar')
    expect(createContainer.firstCall.args[0].Cmd[0]).to.include(
      '--cache-dir /scanner-cache'
    )
    expect(createContainer.firstCall.args[0].Cmd[0]).to.include(
      'ln -s /cache/db /scanner-cache/db'
    )
    expect(createContainer.firstCall.args[0].Cmd[0]).not.to.include(
      '--cache-backend memory'
    )
    expect(JSON.stringify(createContainer.firstCall.args[0].HostConfig)).not.to.include(
      'docker.sock'
    )
    expect(createContainer.firstCall.args[0].HostConfig.Mounts[0]).to.deep.include({
      Type: 'volume',
      Target: '/cache',
      ReadOnly: true
    })
    expect(createContainer.firstCall.args[0].HostConfig.NetworkMode).to.equal('none')
    expect(createContainer.firstCall.args[0].HostConfig.ReadonlyRootfs).to.equal(true)
    expect(createContainer.firstCall.args[0].HostConfig.CapDrop).to.deep.equal(['ALL'])
    expect(container.remove.calledOnce).to.equal(true)
  })

  it('rejects non-zero, empty, invalid, and oversized scanner output', async () => {
    const { engine } = await makeEngine({
      tempFolder,
      scanImages: true,
      severities: ['HIGH']
    })
    allowScannerRun(engine as any)

    for (const [output, status, expected] of [
      ['scanner failed', 2, 'exited with status 2'],
      ['', 0, 'empty report'],
      ['not-json', 0, 'not valid JSON'],
      ['x'.repeat(10 * 1024 * 1024 + 1), 0, 'size limit']
    ] as const) {
      const container = makeScannerContainer(output, status, status !== 0)
      ;(engine as any).docker = { createContainer: sinon.stub().resolves(container) }
      const message = await rejectedMessage(
        (engine as any).checkImageVulnerability('example/image')
      )
      expect(message).to.include(expected)
      expect(container.remove.calledOnce).to.equal(true)
    }
  })

  it('refreshes a missing database before scanning and fails closed if refresh fails', async () => {
    const { engine } = await makeEngine({
      tempFolder,
      scanImages: true,
      severities: ['HIGH']
    })
    ;(engine as any).checkscanDBImage = sinon.stub().resolves()
    ;(engine as any).scanDBUpdate = sinon.stub().callsFake(() => {
      ;(engine as any).trivyDatabaseUpdatedAt = Date.now()
      return Promise.resolve()
    })
    await (engine as any).ensureFreshScanDatabase()
    expect((engine as any).scanDBUpdate.calledOnce).to.equal(true)
    ;(engine as any).trivyDatabaseUpdatedAt = null
    ;(engine as any).scanDBUpdate = sinon.stub().rejects(new Error('refresh failed'))
    ;(engine as any).docker = { createContainer: sinon.stub() }
    const message = await rejectedMessage(
      (engine as any).checkImageVulnerability('example/image')
    )
    expect(message).to.include('refresh failed')
    expect((engine as any).docker.createContainer.notCalled).to.equal(true)
  })

  it('marks the Docker-managed vulnerability database fresh only after update', async () => {
    const { engine } = await makeEngine({
      tempFolder,
      scanImages: true,
      severities: ['HIGH']
    })
    const updater = {
      start: sinon.stub().resolves(),
      wait: sinon.stub().resolves({ StatusCode: 0 }),
      remove: sinon.stub().resolves()
    }
    const createVolume = sinon.stub().resolves()
    const createContainer = sinon.stub().resolves(updater)
    ;(engine as any).docker = {
      getImage: () => ({ inspect: sinon.stub().resolves() }),
      createVolume,
      createContainer
    }

    await Promise.all([(engine as any).scanDBUpdate(), (engine as any).scanDBUpdate()])

    expect(createVolume.calledOnce).to.equal(true)
    expect(createContainer.firstCall.args[0].HostConfig.Mounts[0]).to.deep.include({
      Type: 'volume',
      Target: '/root/.cache/trivy'
    })
    expect(createContainer.firstCall.args[0].HostConfig.Tmpfs['/tmp']).to.equal(
      'rw,noexec,nosuid,nodev,size=536870912'
    )
    expect((engine as any).trivyDatabaseUpdatedAt).to.be.a('number')
    expect(() => (engine as any).assertFreshScanDatabase()).not.to.throw()
  })

  it('stops before volume creation when scanning fails or rejects the image', async () => {
    const { engine, db } = await makeEngine({
      tempFolder,
      scanImages: true,
      severities: ['HIGH']
    })
    const job = makeJob()
    const createVolume = sinon.stub().resolves(true)
    ;(engine as any).createDockerVolume = createVolume
    ;(engine as any).checkImageVulnerability = sinon
      .stub()
      .rejects(new Error('scanner unavailable'))

    await (engine as any).processJob(job)

    expect(job.status).to.equal(C2DStatusNumber.ImageScanFailed)
    expect(createVolume.notCalled).to.equal(true)
    expect(db.updateJob.called).to.equal(true)

    const vulnerableJob = makeJob()
    vulnerableJob.jobId = 'job-vulnerable'
    const vulnerableLogs = path.join(
      engine.getStoragePath(),
      vulnerableJob.jobId,
      'data',
      'logs'
    )
    mkdirSync(vulnerableLogs, { recursive: true })
    writeFileSync(path.join(vulnerableLogs, 'image.log'), '')
    ;(engine as any).checkImageVulnerability = sinon
      .stub()
      .resolves({ vulnerable: true, summary: {} })

    await (engine as any).processJob(vulnerableJob)

    expect(vulnerableJob.status).to.equal(C2DStatusNumber.VulnerableImage)
    expect(createVolume.notCalled).to.equal(true)
  })

  it('does no scanner work when scanning is disabled', async () => {
    const { engine } = await makeEngine({ tempFolder, scanImages: false })
    const job = makeJob()
    const scanner = sinon.stub().rejects(new Error('must not run'))
    ;(engine as any).checkImageVulnerability = scanner
    ;(engine as any).createDockerVolume = sinon.stub().resolves(false)

    await (engine as any).processJob(job)

    expect(scanner.notCalled).to.equal(true)
    expect(job.status).to.equal(C2DStatusNumber.VolumeCreationFailed)
    expect(existsSync(path.join(tempFolder, 'trivy_cache'))).to.equal(false)
  })

  it('cancels scanner and payment timers when the engine stops', async () => {
    const clock = sinon.useFakeTimers()
    const { engine } = await makeEngine({
      tempFolder,
      scanImages: true,
      severities: ['HIGH'],
      scanInterval: 60
    })
    const update = sinon.stub().resolves()
    const paymentClaim = sinon.stub().resolves()
    ;(engine as any).docker = {}
    ;(engine as any).scanDBUpdate = update
    ;(engine as any).claimPayments = paymentClaim
    ;(engine as any).startCrons()

    expect((engine as any).scanDBUpdateInitialTimer).not.to.equal(null)
    expect((engine as any).scanDBUpdateTimer).not.to.equal(null)
    await engine.stop()
    await clock.tickAsync(3_601_000)

    expect(update.notCalled).to.equal(true)
    expect(paymentClaim.notCalled).to.equal(true)
    expect((engine as any).paymentClaimInitialTimer).to.equal(null)
    expect((engine as any).paymentClaimTimer).to.equal(null)
    expect((engine as any).scanDBUpdateInitialTimer).to.equal(null)
    expect((engine as any).scanDBUpdateTimer).to.equal(null)
  })
})
