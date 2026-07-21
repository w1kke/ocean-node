/* eslint-disable security/detect-non-literal-fs-filename */
import { expect } from 'chai'
import sinon from 'sinon'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs'
import os from 'os'
import path from 'path'
import { Readable } from 'stream'

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
      scanImageDBUpdateInterval: null
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

  it('uses one severity list for Trivy and evaluation and removes the scanner', async () => {
    const { engine } = await makeEngine({
      tempFolder,
      scanImages: true,
      severities: ['HIGH', 'CRITICAL']
    })
    const container = makeScannerContainer(JSON.stringify(findingsReport))
    const createContainer = sinon.stub().resolves(container)
    ;(engine as any).checkscanDBImage = sinon.stub().resolves()
    ;(engine as any).docker = { createContainer }

    const result = await (engine as any).checkImageVulnerability('example/image')

    expect(result.vulnerable).to.equal(true)
    expect(createContainer.firstCall.args[0].Cmd).to.include('HIGH,CRITICAL')
    expect(container.remove.calledOnce).to.equal(true)
  })

  it('rejects non-zero, empty, invalid, and oversized scanner output', async () => {
    const { engine } = await makeEngine({
      tempFolder,
      scanImages: true,
      severities: ['HIGH']
    })
    ;(engine as any).checkscanDBImage = sinon.stub().resolves()

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
})
