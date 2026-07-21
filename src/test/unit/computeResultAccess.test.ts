/* eslint-disable security/detect-non-literal-fs-filename */
import { expect } from 'chai'
import sinon from 'sinon'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs'
import os from 'os'
import path from 'path'

import type { DBComputeJob } from '../../@types/C2D/C2D.js'
import { ComputeGetStreamableLogsHandler } from '../../components/core/compute/getStreamableLogs.js'

function ensureTestEnv() {
  if (!process.env.PRIVATE_KEY) process.env.PRIVATE_KEY = `0x${'11'.repeat(32)}`
}

async function streamText(stream: NodeJS.ReadableStream): Promise<string> {
  let result = ''
  for await (const chunk of stream) result += chunk.toString()
  return result
}

describe('consumer compute result access', () => {
  let tempFolder: string

  beforeEach(() => {
    ensureTestEnv()
    tempFolder = mkdtempSync(path.join(os.tmpdir(), 'ocean-result-access-')) + '/'
  })

  afterEach(() => {
    sinon.restore()
    rmSync(tempFolder, { recursive: true, force: true })
  })

  it('advertises and serves output only with a stable index', async () => {
    const { C2DEngineDocker } =
      await import('../../components/c2d/compute_engine_docker.js')
    const jobId = 'job-123'
    const owner = '0x0000000000000000000000000000000000000001'
    const job = {
      jobId,
      owner,
      additionalViewers: ['0x0000000000000000000000000000000000000002']
    } as DBComputeJob
    const db = { getJob: sinon.stub().resolves([job]) } as any
    const cluster = {
      type: 2,
      hash: 'test-hash',
      tempFolder,
      connection: {}
    } as any
    const engine = new C2DEngineDocker(cluster, db, {} as any, {} as any, {} as any)
    const dataPath = path.join(engine.getStoragePath(), jobId, 'data')
    mkdirSync(path.join(dataPath, 'logs'), { recursive: true })
    mkdirSync(path.join(dataPath, 'outputs'), { recursive: true })
    for (const log of [
      'image.log',
      'configuration.log',
      'algorithm.log',
      'publish.log'
    ]) {
      writeFileSync(path.join(dataPath, 'logs', log), `private ${log}`)
    }
    writeFileSync(path.join(dataPath, 'outputs', 'outputs.tar'), 'released output')

    const statuses = await engine.getComputeJobStatus(owner, null, jobId)
    expect(statuses[0].results).to.deep.equal([
      { filename: 'outputs.tar', filesize: 15, type: 'output', index: 0 }
    ])

    const result = await engine.getComputeJobResult(owner, jobId, 0)
    expect(await streamText(result.stream)).to.equal('released output')
    expect(await engine.getComputeJobResult(owner, jobId, 1)).to.equal(null)

    let denied: Error = null
    try {
      await engine.getComputeJobResult(
        '0x0000000000000000000000000000000000000003',
        jobId,
        0
      )
    } catch (error) {
      denied = error as Error
    }
    expect(denied?.message).to.include('not authorized')
  })

  it('keeps the live log route closed after validating the request', async () => {
    const node = {
      getRequestMap: () => new Map(),
      getConfig: () => ({ rateLimit: 100 })
    } as any
    const handler = new ComputeGetStreamableLogsHandler(node)
    const response = await handler.handle({
      command: 'getComputeStreamableLogs',
      jobId: 'hash-job',
      caller: null
    } as any)

    expect(response.status.httpStatus).to.equal(403)
    expect(response.status.error).to.equal('Compute logs are operator-only')
    expect(response.stream).to.equal(null)
  })
})
