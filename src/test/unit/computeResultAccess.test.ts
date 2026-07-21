/* eslint-disable security/detect-non-literal-fs-filename */
import { expect } from 'chai'
import sinon from 'sinon'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs'
import os from 'os'
import path from 'path'
import { Readable } from 'stream'

import type { DBComputeJob } from '../../@types/C2D/C2D.js'
import { Auth } from '../../components/Auth/index.js'
import { ComputeGetResultHandler } from '../../components/core/compute/getResults.js'
import { ComputeGetStatusHandler } from '../../components/core/compute/getStatus.js'
import { ComputeGetStreamableLogsHandler } from '../../components/core/compute/getStreamableLogs.js'
import { sendComputeStatusResponse } from '../../components/httpRoutes/compute.js'
import { redactCommandForLogging } from '../../components/httpRoutes/validateCommands.js'

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
      environment: 'env-1',
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
    sinon
      .stub(engine, 'getComputeEnvironments')
      .resolves([{ id: 'env-1', consumerResultPolicy: { mode: 'archive' } } as any])
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

    const jsonBody = '{"approved":true}'
    writeFileSync(path.join(dataPath, 'outputs', 'result.json'), jsonBody)
    ;(engine.getComputeEnvironments as sinon.SinonStub).resolves([
      {
        id: 'env-1',
        consumerResultPolicy: { mode: 'singleJson', maxBytes: 1024 }
      } as any
    ])
    const strictStatuses = await engine.getComputeJobStatus(owner, null, jobId)
    expect(strictStatuses[0].results).to.deep.equal([
      { filename: 'result.json', filesize: jsonBody.length, type: 'output', index: 0 }
    ])
    const strictResult = await engine.getComputeJobResult(owner, jobId, 0)
    expect(await streamText(strictResult.stream)).to.equal(jsonBody)
    expect(strictResult.headers).to.include({
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'private, no-store',
      'X-Content-Type-Options': 'nosniff'
    })

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

  it('binds bearer tokens to result and status addresses', async () => {
    const owner = '0x0000000000000000000000000000000000000001'
    const attacker = '0x0000000000000000000000000000000000000002'
    const tokenDatabase = {
      validateToken: sinon.stub().resolves({ address: attacker })
    } as any
    const auth = new Auth(tokenDatabase, { jwtSecret: 'test-secret' } as any)
    const engine = {
      getComputeJobResult: sinon.stub().resolves({
        stream: Readable.from('result'),
        headers: {}
      }),
      getComputeJobStatus: sinon.stub().resolves([])
    }
    const node = {
      getRequestMap: () => new Map(),
      getConfig: () => ({ rateLimit: 100 }),
      getAuth: () => auth,
      getC2DEngines: () => ({
        getC2DByHash: sinon.stub().resolves(engine),
        getAllEngines: sinon.stub().resolves([engine])
      })
    } as any

    const resultResponse = await new ComputeGetResultHandler(node).handle({
      command: 'getComputeResult',
      authorization: 'attacker-token',
      consumerAddress: owner,
      jobId: 'hash-job',
      index: 0
    } as any)
    const statusResponse = await new ComputeGetStatusHandler(node).handle({
      command: 'getComputeStatus',
      authorization: 'attacker-token',
      consumerAddress: owner,
      jobId: 'hash-job'
    } as any)

    expect(resultResponse.status).to.include({ httpStatus: 401 })
    expect(statusResponse.status).to.include({ httpStatus: 401 })
    expect(engine.getComputeJobResult.notCalled).to.equal(true)
    expect(engine.getComputeJobStatus.notCalled).to.equal(true)
  })

  it('preserves status authorization errors at the HTTP boundary', async () => {
    const response = {
      stream: null,
      status: { httpStatus: 401, error: 'Invalid token' }
    } as any
    const send = sinon.stub()
    const json = sinon.stub()
    const status = sinon.stub().returns({ send, json })

    await sendComputeStatusResponse({ status } as any, response)

    expect(status.calledOnceWith(401)).to.equal(true)
    expect(send.calledOnceWith('Invalid token')).to.equal(true)
    expect(json.notCalled).to.equal(true)
  })

  it('preserves stream-bearing status errors at the HTTP boundary', async () => {
    const response = {
      stream: Readable.from('Rate limit exceeded'),
      status: { httpStatus: 403, error: 'Rate limit exceeded' }
    } as any
    const send = sinon.stub()
    const json = sinon.stub()
    const status = sinon.stub().returns({ send, json })

    await sendComputeStatusResponse({ status } as any, response)

    expect(status.calledOnceWith(403)).to.equal(true)
    expect(send.calledOnceWith('Rate limit exceeded')).to.equal(true)
    expect(json.notCalled).to.equal(true)
  })

  it('redacts replayable authentication material from command logs', () => {
    const redacted = redactCommandForLogging({
      command: 'getComputeStatus',
      authorization: 'Bearer secret-token',
      signature: '0xsigned',
      token: 'secret-token',
      files: [
        {
          headers: { Authorization: 'Bearer nested-token' },
          s3Access: { accessKeyId: 'public-id', secretAccessKey: 'nested-secret' }
        }
      ],
      consumerAddress: '0x0000000000000000000000000000000000000001'
    })

    expect(redacted).to.deep.equal({
      command: 'getComputeStatus',
      authorization: '[REDACTED]',
      signature: '[REDACTED]',
      token: '[REDACTED]',
      files: [
        {
          headers: '[REDACTED]',
          s3Access: { accessKeyId: '[REDACTED]', secretAccessKey: '[REDACTED]' }
        }
      ],
      consumerAddress: '0x0000000000000000000000000000000000000001'
    })
  })

  it('uses the token address when status omits a consumer address', async () => {
    const owner = '0x0000000000000000000000000000000000000001'
    const tokenDatabase = {
      validateToken: sinon.stub().resolves({ address: owner })
    } as any
    const auth = new Auth(tokenDatabase, { jwtSecret: 'test-secret' } as any)
    const engine = {
      getComputeJobStatus: sinon.stub().resolves([{ jobId: 'job' }])
    }
    const node = {
      getRequestMap: () => new Map(),
      getConfig: () => ({ rateLimit: 100 }),
      getAuth: () => auth,
      getC2DEngines: () => ({
        getC2DByHash: sinon.stub().resolves(engine)
      })
    } as any

    const response = await new ComputeGetStatusHandler(node).handle({
      command: 'getComputeStatus',
      authorization: 'owner-token',
      jobId: 'hash-job'
    } as any)

    expect(response.status.httpStatus).to.equal(200)
    expect(engine.getComputeJobStatus.calledOnceWith(owner, undefined, 'job')).to.equal(
      true
    )
    expect(tokenDatabase.validateToken.calledOnce).to.equal(true)
  })

  it('maps missing and unauthorized results at the handler boundary', async () => {
    const owner = '0x0000000000000000000000000000000000000001'
    const auth = {
      validateAuthenticationOrToken: sinon.stub().resolves({
        valid: true,
        error: '',
        authenticatedAddress: owner
      })
    }
    const engine = { getComputeJobResult: sinon.stub().resolves(null) }
    const node = {
      getRequestMap: () => new Map(),
      getConfig: () => ({ rateLimit: 100 }),
      getAuth: () => auth,
      getC2DEngines: () => ({ getC2DByHash: sinon.stub().resolves(engine) })
    } as any
    const handler = new ComputeGetResultHandler(node)
    const task = {
      command: 'getComputeResult',
      consumerAddress: owner,
      signature: 'signature',
      nonce: '1',
      jobId: 'hash-job',
      index: 0
    } as any

    expect((await handler.handle(task)).status.httpStatus).to.equal(404)
    expect(auth.validateAuthenticationOrToken.firstCall.args[0].command).to.equal(
      'getComputeResult:hash-job:0'
    )
    engine.getComputeJobResult.rejects(new Error(`${owner} is not authorized`))
    expect((await handler.handle(task)).status.httpStatus).to.equal(403)
  })
})
