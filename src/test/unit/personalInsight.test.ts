/* eslint-disable security/detect-non-literal-fs-filename */
import { expect } from 'chai'
import axios from 'axios'
import express from 'express'
import { createHash } from 'crypto'
import { createServer, Server } from 'http'
import { AddressInfo } from 'net'
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
import type { DBComputeJob, PersonalInsightPolicy } from '../../@types/C2D/C2D.js'
import {
  claimPersonalInsightGrant,
  completePersonalInsightRun,
  consumePersonalInsightCapability,
  downloadPersonalInsightDataset,
  PersonalInsightError,
  revalidatePersonalInsightRun,
  validatePersonalInsightInput,
  validatePersonalInsightResult
} from '../../components/c2d/personalInsight.js'
import { C2DEngineDocker } from '../../components/c2d/compute_engine_docker.js'
import {
  C2DDockerConfigSchema,
  C2DEnvironmentConfigSchema
} from '../../utils/config/schemas.js'
import { personalInsightRoutes } from '../../components/httpRoutes/personalInsight.js'

const JOB_ID = 'a'.repeat(64)
const RUN_ID = 'b'.repeat(32)
const GRANT = `grant-id.${'c'.repeat(43)}`
const CAPABILITY = `capability-id.${'d'.repeat(43)}`
const IMAGE = `brainstem/personal-resting@sha256:${'e'.repeat(64)}`
const RESULT_CHECKSUM = 'f'.repeat(64)
const BFF_TOKEN = 'generated-personal-bff-token-long-enough'

function policy(crabUrl: string): PersonalInsightPolicy {
  return {
    crabUrl,
    allowInsecureLocalProof: crabUrl.startsWith('http://'),
    approvedAlgorithmImage: IMAGE,
    bearerTokenEnv: 'PERSONAL_INSIGHT_TEST_TOKEN',
    bffBearerTokenEnv: 'PERSONAL_INSIGHT_BFF_TEST_TOKEN',
    ramWorkspaceRoot: '/dev/shm/brainstem-personal-insight-test',
    inputSchema: 'brainstem.personal-resting-rr/v1',
    inputPolicy: 'brainstem.personal-resting-rr/latest-16/v1',
    resultContract: 'brainstem.c2d-result/v1',
    resultProfile: 'brainstem.personal-resting-heart-overview/v1',
    audience: 'brainstem-ocean-node',
    maxInputBytes: 1024 * 1024,
    maxResultBytes: 256 * 1024,
    maxJobDuration: 120,
    resources: { cpu: 1, ram: 1 }
  }
}

function input() {
  return {
    schema: 'brainstem.personal-resting-rr/v1',
    policy: 'brainstem.personal-resting-rr/latest-16/v1',
    recordings: [
      {
        recordingType: 'rest',
        durationSeconds: 300,
        rrIntervalsMs: [800, 805, 798, 802]
      }
    ]
  }
}

function result(): any {
  return {
    schema: 'brainstem.c2d-result/v1',
    status: 'complete',
    title: 'My resting heart overview',
    summary:
      'This overview describes the qualifying resting recordings used for this result.',
    metrics: [
      { label: 'Qualifying recordings', value: 1, unit: 'count' },
      { label: 'Typical R-R interval', value: 801, unit: 'ms' },
      { label: 'Typical resting rate', value: 74.9, unit: 'bpm' }
    ],
    charts: [
      {
        type: 'line',
        title: 'Resting rate by recording',
        x: { label: 'Recording', values: [1] },
        y: { label: 'Resting rate', unit: 'bpm' },
        series: [{ label: 'Derived resting rate', values: [74.9] }]
      }
    ],
    table: null,
    warnings: [
      'Personal overview only. Not a diagnosis or medical advice. Contact a qualified clinician if you have health concerns.'
    ],
    provenance: {
      algorithmVersion: '1.0.0',
      algorithmImageDigest: `sha256:${'e'.repeat(64)}`,
      datasetSchemaVersion: 'brainstem.personal-resting-rr/v1',
      generatedAt: '2026-07-27T07:00:00Z'
    }
  }
}

describe('personal Insight boundary', () => {
  const environment = {
    PERSONAL_INSIGHT_TEST_TOKEN: 'generated-personal-test-token-long-enough',
    PERSONAL_INSIGHT_BFF_TEST_TOKEN: BFF_TOKEN
  }
  let server: Server
  let crabUrl: string
  let directory: string
  let requests: Array<{ url: string; authorization: string; body: any; headers: any }>
  let revalidationStatus: number
  let capabilityStatus: number

  beforeEach(async () => {
    process.env.PERSONAL_INSIGHT_TEST_TOKEN = 'generated-personal-test-token-long-enough'
    process.env.PERSONAL_INSIGHT_BFF_TEST_TOKEN = BFF_TOKEN
    requests = []
    revalidationStatus = 200
    capabilityStatus = 200
    const dataset = Buffer.from(JSON.stringify(input()))
    server = createServer((request, response) => {
      const chunks: Buffer[] = []
      request.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
      request.on('end', () => {
        const raw = Buffer.concat(chunks)
        const body = raw.length ? JSON.parse(raw.toString()) : null
        requests.push({
          url: request.url!,
          authorization: String(request.headers.authorization ?? ''),
          body,
          headers: request.headers
        })
        if (request.url?.endsWith('/grants/claim')) {
          response.writeHead(200, { 'Content-Type': 'application/json' })
          response.end(
            JSON.stringify({
              result: {
                status: 'claimed',
                expiresAt: '2026-07-27T07:05:00Z',
                algorithmImageDigest: IMAGE.split('@').at(-1),
                inputSchema: 'brainstem.personal-resting-rr/v1',
                inputPolicy: 'brainstem.personal-resting-rr/latest-16/v1',
                resultSchema: 'brainstem.c2d-result/v1',
                resultProfile: 'brainstem.personal-resting-heart-overview/v1',
                maximumRecordings: 16,
                audience: 'brainstem-ocean-node'
              }
            })
          )
          return
        }
        if (request.url?.endsWith('/runs/complete')) {
          response.writeHead(200, { 'Content-Type': 'application/json' })
          response.end(
            JSON.stringify({
              result: {
                status: 'complete',
                resultExpiresAt: '2026-08-10T07:00:00Z'
              }
            })
          )
          return
        }
        if (request.url?.endsWith('/runs/revalidate')) {
          if (revalidationStatus !== 200) {
            response.writeHead(revalidationStatus, {
              'Content-Type': 'application/json'
            })
            response.end(JSON.stringify({ error: 'not_found' }))
            return
          }
          response.writeHead(200, { 'Content-Type': 'application/json' })
          response.end(
            JSON.stringify({
              result: {
                status: 'authorized',
                jobId: JOB_ID,
                runId: RUN_ID
              }
            })
          )
          return
        }
        if (request.url?.endsWith('/capabilities/consume')) {
          if (capabilityStatus !== 200) {
            response.writeHead(capabilityStatus, {
              'Content-Type': 'application/json'
            })
            response.end(JSON.stringify({ error: 'not_found' }))
            return
          }
          response.writeHead(200, { 'Content-Type': 'application/json' })
          response.end(
            JSON.stringify({
              result: {
                status: 'authorized',
                action: body.action,
                runId: RUN_ID,
                resultSha256: body.action === 'result' ? RESULT_CHECKSUM : null
              }
            })
          )
          return
        }
        const checksum = createHash('sha256').update(dataset).digest('hex')
        response.writeHead(200, {
          'Content-Type': 'application/json',
          'Content-Length': dataset.length,
          'X-Content-SHA256': checksum
        })
        response.end(dataset)
      })
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address() as AddressInfo
    crabUrl = `http://127.0.0.1:${address.port}/`
    directory = mkdtempSync(path.join(os.tmpdir(), 'personal-insight-test-'))
  })

  afterEach(async () => {
    delete process.env.PERSONAL_INSIGHT_TEST_TOKEN
    delete process.env.PERSONAL_INSIGHT_BFF_TEST_TOKEN
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    )
    rmSync(directory, { recursive: true, force: true })
  })

  it('binds claim, one fetch, completion and one-use action checks to Crab', async () => {
    const configured = policy(crabUrl)
    await claimPersonalInsightGrant(configured, GRANT, JOB_ID, RUN_ID, environment)
    const destination = path.join(directory, 'dataset.json')
    const fetched = await downloadPersonalInsightDataset(
      configured,
      GRANT,
      JOB_ID,
      destination,
      environment
    )
    await completePersonalInsightRun(
      configured,
      GRANT,
      JOB_ID,
      RUN_ID,
      RESULT_CHECKSUM,
      environment
    )
    await revalidatePersonalInsightRun(configured, GRANT, JOB_ID, RUN_ID, environment)
    expect(
      await consumePersonalInsightCapability(
        configured,
        CAPABILITY,
        RUN_ID,
        'status',
        environment
      )
    ).to.equal(null)
    expect(
      await consumePersonalInsightCapability(
        configured,
        CAPABILITY,
        RUN_ID,
        'result',
        environment
      )
    ).to.equal(RESULT_CHECKSUM)

    expect(requests.map(({ url }) => url)).to.deep.equal([
      '/api/v1/internal/personal-insights/grants/claim',
      '/api/v1/internal/personal-insights/dataset',
      '/api/v1/internal/personal-insights/runs/complete',
      '/api/v1/internal/personal-insights/runs/revalidate',
      '/api/v1/internal/personal-insights/capabilities/consume',
      '/api/v1/internal/personal-insights/capabilities/consume'
    ])
    expect(
      requests.every(
        ({ authorization }) =>
          authorization === 'Bearer generated-personal-test-token-long-enough'
      )
    ).to.equal(true)
    expect(requests[0].body).to.deep.equal({
      grant: GRANT,
      jobId: JOB_ID,
      runId: RUN_ID
    })
    expect(requests[1].headers['x-brainstem-personal-grant']).to.equal(GRANT)
    expect(requests[1].headers['x-ocean-compute-job-id']).to.equal(JOB_ID)
    expect(JSON.parse(readFileSync(destination, 'utf8'))).to.deep.equal(input())
    expect(fetched.bytes).to.equal(readFileSync(destination).length)
  })

  it('validates the exact personal input and result profile', () => {
    const configured = policy('https://crab.internal/')
    expect(() =>
      validatePersonalInsightInput(Buffer.from(JSON.stringify(input())))
    ).not.to.throw()
    expect(() =>
      validatePersonalInsightResult(Buffer.from(JSON.stringify(result())), configured)
    ).not.to.throw()

    const wrongInput = { ...input(), participant: 'must-not-enter-compute' }
    expect(() =>
      validatePersonalInsightInput(Buffer.from(JSON.stringify(wrongInput)))
    ).to.throw(PersonalInsightError, 'personal_insight_dataset_invalid')
    const wrongResult = result()
    wrongResult.metrics[0].value = 2
    expect(() =>
      validatePersonalInsightResult(Buffer.from(JSON.stringify(wrongResult)), configured)
    ).to.throw(PersonalInsightError, 'personal_insight_result_invalid')
  })

  it('keeps the personal environment unavailable through generic compute access', async () => {
    const job = {
      jobId: JOB_ID,
      environment: 'personal-env',
      owner: '0x0000000000000000000000000000000000000001'
    } as DBComputeJob
    const db = {
      getJob: () => Promise.resolve([job])
    }
    const engine = new C2DEngineDocker(
      {
        type: 2,
        hash: 'test',
        tempFolder: `${directory}/`,
        connection: {}
      } as any,
      db as any,
      {} as any,
      {} as any,
      {} as any
    )
    engine.docker = {} as any
    ;(engine as any).envs = [{ id: 'personal-env' }]
    ;(engine as any).personalInsightPolicies.set(
      'personal-env',
      policy('https://crab.internal/')
    )

    expect(await engine.getComputeEnvironments()).to.deep.equal([])
    expect(await engine.getComputeJobStatus(job.owner, null, JOB_ID)).to.deep.equal([])
    try {
      await engine.startComputeJob(
        [],
        {} as any,
        null,
        'personal-env',
        job.owner,
        120,
        [],
        null,
        JOB_ID
      )
      expect.fail('generic compute must not select the personal environment')
    } catch (error) {
      expect((error as Error).message).to.include('Invalid environment')
    }
    try {
      await engine.getComputeJobResult(job.owner, JOB_ID, 0)
      expect.fail('generic result access must fail')
    } catch (error) {
      expect((error as Error).message).to.include('Cannot find job')
    }
  })

  it('retains a validated result only after Crab accepts its checksum', async () => {
    const resultBytes = Buffer.from(JSON.stringify(result()))
    const resultSha256 = createHash('sha256').update(resultBytes).digest('hex')
    const finishedAt = Math.floor(Date.now() / 1000)
    const job = {
      jobId: JOB_ID,
      jobIdHash: createHash('sha256').update(JOB_ID).digest('hex'),
      personalInsightRunId: RUN_ID,
      personalInsightState: 'pending',
      environment: 'personal-env',
      owner: '0x0000000000000000000000000000000000000001',
      dateCreated: String(finishedAt - 10),
      dateFinished: String(finishedAt),
      status: 70,
      statusText: 'Job finished',
      results: [],
      clusterHash: 'test',
      configlogURL: null,
      publishlogURL: null,
      algologURL: null,
      outputsURL: null,
      stopRequested: false,
      algorithm: {},
      assets: [],
      isRunning: false,
      isStarted: true,
      containerImage: IMAGE,
      isFree: true,
      algoStartTimestamp: String(finishedAt - 5),
      algoStopTimestamp: String(finishedAt - 1),
      resources: [],
      resultValidation: {
        contract: 'brainstem.c2d-result/v1',
        status: 'complete',
        billable: true
      },
      privateInputChecksum: '1'.repeat(64),
      terminationDetails: { exitCode: 0, OOMKilled: false },
      algoDuration: 4,
      queueMaxWaitTime: 0,
      buildStartTimestamp: '0',
      buildStopTimestamp: '0'
    } as DBComputeJob
    const db = {
      updateJob: () => Promise.resolve(1),
      getJob: () => Promise.resolve([job]),
      getJobs: () => Promise.resolve([job])
    }
    const engine = new C2DEngineDocker(
      {
        type: 2,
        hash: 'test',
        tempFolder: `${directory}/`,
        connection: {}
      } as any,
      db as any,
      {} as any,
      {} as any,
      {} as any
    )
    ;(engine as any).personalInsightPolicies.set('personal-env', policy(crabUrl))
    ;(engine as any).personalInsightGrants.set(JOB_ID, GRANT)
    const outputDirectory = path.join(engine.getStoragePath(), JOB_ID, 'data', 'outputs')
    mkdirSync(outputDirectory, { recursive: true })
    writeFileSync(path.join(outputDirectory, 'result.json'), resultBytes)

    expect(await (engine as any).cleanupPrivateJobMaterial(job)).to.equal(true)
    expect(job.personalInsightState).to.equal('complete')
    expect(job.privateResultRetention?.resultChecksum).to.equal(resultSha256)
    expect(
      requests.some(
        ({ url, body }) =>
          url === '/api/v1/internal/personal-insights/runs/complete' &&
          body.resultSha256 === resultSha256
      )
    ).to.equal(true)

    const retainedResultPath = (engine as any).getRetainedPrivateResultPath(job)
    const requestsBeforeWrongBff = requests.length
    try {
      await engine.revalidatePersonalInsight(GRANT, RUN_ID, 'Bearer wrong')
      expect.fail('wrong BFF authorization must fail')
    } catch (error) {
      expect((error as PersonalInsightError).terminal).to.equal(false)
    }
    expect(requests.length).to.equal(requestsBeforeWrongBff)
    expect(job.personalInsightState).to.equal('complete')
    expect(existsSync(retainedResultPath)).to.equal(true)

    capabilityStatus = 409
    try {
      await engine.getPersonalInsightStatus(RUN_ID, CAPABILITY)
      expect.fail('a replayed capability must fail')
    } catch (error) {
      expect((error as PersonalInsightError).terminal).to.equal(false)
    }
    expect(job.personalInsightState).to.equal('complete')
    expect(existsSync(retainedResultPath)).to.equal(true)

    revalidationStatus = 409
    try {
      await engine.revalidatePersonalInsight(GRANT, RUN_ID, `Bearer ${BFF_TOKEN}`)
      expect.fail('a replay conflict must fail')
    } catch (error) {
      expect((error as PersonalInsightError).terminal).to.equal(false)
    }
    expect(job.personalInsightState).to.equal('complete')
    expect(existsSync(retainedResultPath)).to.equal(true)

    revalidationStatus = 410
    await engine.revalidatePersonalInsight(GRANT, RUN_ID, `Bearer ${BFF_TOKEN}`)
    expect(job.personalInsightState).to.equal('rejected')
    expect(existsSync(retainedResultPath)).to.equal(false)
    expect(job.privateResultRetention?.inputChecksum).to.equal(undefined)
  })

  it('accepts only a scanned, networkless, fixed personal policy', () => {
    const personalInsight = policy('https://crab.internal/')
    const configured = {
      storageExpiry: 14 * 24 * 60 * 60,
      maxJobDuration: 120,
      enableNetwork: false,
      resources: [
        { id: 'cpu', total: 2 },
        { id: 'ram', total: 2 },
        { id: 'disk', total: 1 }
      ],
      consumerResultPolicy: {
        mode: 'singleJson',
        maxBytes: 256 * 1024,
        resultContract: 'brainstem.c2d-result/v1'
      },
      personalInsight
    }
    expect(C2DEnvironmentConfigSchema.safeParse(configured).success).to.equal(true)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...configured,
        enableNetwork: true
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...configured,
        personalInsight: {
          ...personalInsight,
          bffBearerTokenEnv: personalInsight.bearerTokenEnv
        }
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...configured,
        privateDataset: {
          url: 'https://crab.internal/cohort',
          maxBytes: 1024,
          approvedAlgorithmImage: IMAGE,
          bearerTokenEnv: 'COHORT_TOKEN',
          releaseId: '1'.repeat(64)
        }
      }).success
    ).to.equal(false)
    expect(
      C2DDockerConfigSchema.safeParse([{ scanImages: false, environments: [configured] }])
        .success
    ).to.equal(false)
    expect(
      C2DDockerConfigSchema.safeParse([
        {
          scanImages: true,
          scanImageRejectSeverities: ['HIGH', 'CRITICAL'],
          environments: [configured]
        }
      ]).success
    ).to.equal(true)

    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...configured,
        personalInsight: {
          ...personalInsight,
          crabUrl: 'http://crab-personal:8089/',
          allowInsecureLocalProof: false
        }
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...configured,
        personalInsight: {
          ...personalInsight,
          crabUrl: 'http://crab-personal:8089/',
          allowInsecureLocalProof: true
        }
      }).success
    ).to.equal(true)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...configured,
        personalInsight: {
          ...personalInsight,
          crabUrl: 'http://crab.example.com/',
          allowInsecureLocalProof: true
        }
      }).success
    ).to.equal(false)
  })

  it('rejects unfinished personal jobs after a process restart', async () => {
    const updates: DBComputeJob[] = []
    const job = {
      jobId: JOB_ID,
      personalInsightRunId: RUN_ID,
      personalInsightState: 'pending',
      environment: 'personal-env',
      owner: '0x0000000000000000000000000000000000000001',
      dateCreated: String(Math.floor(Date.now() / 1000) - 10),
      dateFinished: '',
      status: 40,
      statusText: 'Running algorithm',
      results: [],
      clusterHash: 'test',
      configlogURL: null,
      publishlogURL: null,
      algologURL: null,
      outputsURL: null,
      stopRequested: false,
      algorithm: {},
      assets: [],
      isRunning: true,
      isStarted: true,
      containerImage: IMAGE,
      isFree: true,
      algoStartTimestamp: String(Math.floor(Date.now() / 1000) - 5),
      algoStopTimestamp: '0',
      resources: [],
      algoDuration: 0,
      queueMaxWaitTime: 0,
      buildStartTimestamp: '0',
      buildStopTimestamp: '0'
    } as DBComputeJob
    const db = {
      getJobs: () => Promise.resolve([job]),
      getFinishedJobs: () => Promise.resolve([job]),
      updateJob: (updated: DBComputeJob) => {
        updates.push({ ...updated })
        return Promise.resolve(1)
      }
    }
    const engine = new C2DEngineDocker(
      {
        type: 2,
        hash: 'test',
        tempFolder: `${directory}/`,
        connection: {}
      } as any,
      db as any,
      {} as any,
      {} as any,
      {} as any
    )
    engine.docker = {
      getContainer: () => ({ remove: () => Promise.resolve() }),
      getVolume: () => ({ remove: () => Promise.resolve() })
    } as any
    ;(engine as any).personalInsightPolicies.set(
      'personal-env',
      policy('https://crab.internal/')
    )
    ;(engine as any).personalInsightGrants.set(JOB_ID, GRANT)
    const jobDirectory = path.join(engine.getStoragePath(), JOB_ID)
    mkdirSync(jobDirectory, { recursive: true })

    await (engine as any).recoverPrivateJobMaterial()

    expect(job.personalInsightState).to.equal('rejected')
    expect(job.isRunning).to.equal(false)
    expect(job.stopRequested).to.equal(true)
    expect(job.privateResultRetention?.resultChecksum).to.equal(undefined)
    expect(existsSync(jobDirectory)).to.equal(false)
    expect((engine as any).personalInsightGrants.has(JOB_ID)).to.equal(false)
    expect(
      updates.some((updated) => updated.personalInsightState === 'rejected')
    ).to.equal(true)
  })

  it('exposes only exact grant and capability bodies with safe errors', async () => {
    const app = express()
    app.use(express.json())
    app.use((request, _response, next) => {
      request.oceanNode = {
        getC2DEngines: () => ({
          startPersonalInsight: () => Promise.resolve({ runId: RUN_ID }),
          getPersonalInsightStatus: () => Promise.resolve({ status: 'complete' }),
          revalidatePersonalInsight: (
            grant: string,
            runId: string,
            authorization: string
          ) => {
            if (
              grant !== GRANT ||
              runId !== RUN_ID ||
              authorization !== `Bearer ${BFF_TOKEN}`
            ) {
              return Promise.reject(new Error('not_found'))
            }
            return Promise.resolve()
          },
          getPersonalInsightResult: () =>
            Promise.resolve({
              bytes: Buffer.from(JSON.stringify(result())),
              checksum: RESULT_CHECKSUM
            })
        })
      } as any
      next()
    })
    app.use(personalInsightRoutes)
    const routeServer = app.listen(0, '127.0.0.1')
    await new Promise<void>((resolve) => routeServer.once('listening', resolve))
    const address = routeServer.address() as AddressInfo
    const base = `http://127.0.0.1:${address.port}/api/services/personal-insights/runs`
    try {
      const start = await axios.post(`${base}/start`, { grant: GRANT })
      expect(start.status).to.equal(202)
      expect(start.data).to.deep.equal({ runId: RUN_ID })
      const status = await axios.post(`${base}/status`, {
        runId: RUN_ID,
        capability: CAPABILITY
      })
      expect(status.data).to.deep.equal({ status: 'complete' })
      const unauthorizedRevalidation = await axios.post(
        `${base}/revalidate`,
        { grant: GRANT, runId: RUN_ID },
        { validateStatus: () => true }
      )
      expect(unauthorizedRevalidation.status).to.equal(404)
      const revalidation = await axios.post(
        `${base}/revalidate`,
        { grant: GRANT, runId: RUN_ID },
        { headers: { Authorization: `Bearer ${BFF_TOKEN}` } }
      )
      expect(revalidation.status).to.equal(204)
      const response = await axios.post(`${base}/result`, {
        runId: RUN_ID,
        capability: CAPABILITY
      })
      expect(response.headers['x-content-sha256']).to.equal(RESULT_CHECKSUM)
      expect(response.headers['cache-control']).to.equal('private, no-store')
      const rejected = await axios.post(
        `${base}/start`,
        { grant: GRANT, environment: 'caller-controlled' },
        { validateStatus: () => true }
      )
      expect(rejected.status).to.equal(404)
      expect(rejected.data).to.deep.equal({ error: 'not_found' })
    } finally {
      await new Promise<void>((resolve, reject) =>
        routeServer.close((error) => (error ? reject(error) : resolve()))
      )
    }
  })
})
