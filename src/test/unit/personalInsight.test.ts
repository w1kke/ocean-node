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
  consumePersonalInsightHistoryCapability,
  downloadPersonalInsightDataset,
  PersonalInsightError,
  revalidatePersonalInsightHistory,
  revalidatePersonalInsightRun,
  validatePersonalInsightInput,
  validatePersonalInsightResult
} from '../../components/c2d/personalInsight.js'
import {
  C2DEngineDocker,
  getPersonalInsightImageExecution
} from '../../components/c2d/compute_engine_docker.js'
import {
  C2DDockerConfigSchema,
  C2DEnvironmentConfigSchema
} from '../../utils/config/schemas.js'
import { personalInsightRoutes } from '../../components/httpRoutes/personalInsight.js'

const JOB_ID = 'a'.repeat(64)
const RUN_ID = 'b'.repeat(32)
const HISTORY_ID = '0'.repeat(64)
const GRANT = `grant-id.${'c'.repeat(43)}`
const CAPABILITY = `capability-id.${'d'.repeat(43)}`
const IMAGE = `brainstem/personal-resting@sha256:${'e'.repeat(64)}`
const RESULT_CHECKSUM = 'f'.repeat(64)
const BFF_TOKEN = 'generated-personal-bff-token-long-enough'
const ANALYSIS_ID = 'brainstem.personal-resting-heart-overview/v1'
const METHODS_ANALYSIS_ID = 'brainstem.resting-hrv-methods/v1'
const SAMPLE_ENTROPY_ANALYSIS_ID = 'brainstem.resting-rr-sample-entropy/v1'
const SLEEP_BASELINE_ANALYSIS_ID = 'brainstem.sleep-baseline/v1'
const METHODS_CANDIDATE_SHA256 =
  '15dbf8544c87d81c06f5e512b00e9fe39dd6431dd1a4079a97da68a3f92721c1'
const METHODS_APPROVED_SHA256 = '1'.repeat(64)
const METHODS_REFERENCE_SHA256 =
  '8fb8f2fb8b04af06c002412fc5c8aea94f9a59e9703ccd7943139eb1ded79b15'
const SAMPLE_ENTROPY_CANDIDATE_SHA256 =
  '65002ab13f02f812c611085c0295b81dc90ec7ffacc79f9ff4927e81e9070bdd'
const SLEEP_BASELINE_CANDIDATE_SHA256 =
  '4c24414518539dd6ff2c1a166e6d588f01e3a3fa9572111fb15b6729c7c7300e'

function policy(crabUrl: string): PersonalInsightPolicy {
  return {
    analysisId: ANALYSIS_ID,
    algorithmVersion: '1.0.0',
    crabUrl,
    allowInsecureLocalProof: crabUrl.startsWith('http://'),
    approvedAlgorithmImage: IMAGE,
    candidateManifestSha256: null,
    approvedManifestSha256: null,
    referenceSha256: null,
    evidenceTier: 'E2_brainstem_compatible_exploratory',
    useClass: 'methods_only',
    clinicalUse: 'prohibited',
    bearerTokenEnv: 'PERSONAL_INSIGHT_TEST_TOKEN',
    bffBearerTokenEnv: 'PERSONAL_INSIGHT_BFF_TEST_TOKEN',
    ramWorkspaceRoot: '/dev/shm/brainstem-personal-insight-test',
    inputSchema: 'brainstem.personal-resting-rr/v1',
    inputPolicy: 'brainstem.personal-resting-rr/latest-16/v1',
    resultContract: 'brainstem.c2d-result/v1',
    resultProfile: 'brainstem.personal-resting-heart-overview/v1',
    audience: 'brainstem-ocean-node',
    maximumRecordings: 16,
    maxInputBytes: 1024 * 1024,
    maxResultBytes: 256 * 1024,
    maxJobDuration: 120,
    resources: { cpu: 1, ram: 1 }
  }
}

function methodsPolicy(crabUrl: string): PersonalInsightPolicy {
  return {
    ...policy(crabUrl),
    analysisId: METHODS_ANALYSIS_ID,
    algorithmVersion: '0.1.0',
    candidateManifestSha256: METHODS_CANDIDATE_SHA256,
    approvedManifestSha256: METHODS_APPROVED_SHA256,
    referenceSha256: METHODS_REFERENCE_SHA256,
    inputSchema: 'brainstem.personal-resting-hrv-methods/v1',
    inputPolicy: 'brainstem.personal-resting-hrv-methods/latest-16/v1',
    resultContract: 'brainstem.insight-result/v1',
    resultProfile: 'brainstem.resting-hrv-methods-personal/v1'
  }
}

function sampleEntropyPolicy(crabUrl: string): PersonalInsightPolicy {
  return {
    ...policy(crabUrl),
    analysisId: SAMPLE_ENTROPY_ANALYSIS_ID,
    algorithmVersion: '0.1.0',
    candidateManifestSha256: SAMPLE_ENTROPY_CANDIDATE_SHA256,
    approvedManifestSha256: '2'.repeat(64),
    referenceSha256: '3'.repeat(64),
    inputSchema: 'brainstem.personal-resting-sample-entropy/v1',
    inputPolicy: 'brainstem.personal-resting-sample-entropy/latest-4/v1',
    resultContract: 'brainstem.insight-result/v1',
    resultProfile: 'brainstem.resting-sample-entropy-personal/v1',
    maximumRecordings: 4
  }
}

function sleepBaselinePolicy(crabUrl: string): PersonalInsightPolicy {
  return {
    ...policy(crabUrl),
    analysisId: SLEEP_BASELINE_ANALYSIS_ID,
    algorithmVersion: '0.1.0',
    candidateManifestSha256: SLEEP_BASELINE_CANDIDATE_SHA256,
    approvedManifestSha256: '4'.repeat(64),
    referenceSha256: '5'.repeat(64),
    inputSchema: 'brainstem.personal-sleep-baseline/v1',
    inputPolicy: 'brainstem.personal-sleep-baseline/latest-7/v1',
    resultContract: 'brainstem.insight-result/v1',
    resultProfile: 'brainstem.sleep-baseline-personal/v1',
    maximumRecordings: 7,
    maxInputBytes: 8 * 1024 * 1024
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

function methodsInput(): any {
  return {
    schema: 'brainstem.personal-resting-hrv-methods/v1',
    recordings: [
      {
        recordingType: 'rest',
        durationSeconds: 300,
        rrIntervalsMs: Array.from(
          { length: 330 },
          (_, index) => 900 + 20 * Math.sin(index / 11)
        )
      }
    ]
  }
}

function methodsResult(): any {
  return {
    schema: 'brainstem.insight-result/v1',
    analysisId: METHODS_ANALYSIS_ID,
    scope: 'personal',
    status: 'complete',
    abstentionReason: null,
    evidence: {
      tier: 'E2_brainstem_compatible_exploratory',
      useClass: 'methods_only',
      clinicalUse: 'prohibited'
    },
    paperClassification: {
      decision: 'not_applicable',
      label: null,
      score: null
    },
    title: 'Resting heart variability methods',
    summary:
      'Your compatible resting recordings compared with a frozen aggregate reference.',
    metrics: [
      { label: 'SDNN', value: 14.2, unit: 'ms' },
      { label: 'RMSSD', value: 1.4, unit: 'ms' }
    ],
    charts: [
      {
        type: 'bar',
        title: 'Time-domain measures',
        x: { label: 'Method', values: ['SDNN', 'RMSSD'] },
        y: { label: 'Value', unit: 'ms' },
        series: [{ label: 'Result', values: [14.2, 1.4] }]
      }
    ],
    table: {
      title: 'Personal result and aggregate comparison',
      columns: [
        { label: 'Measure' },
        { label: 'Value', unit: 'ms' },
        { label: 'Comparison' }
      ],
      rows: [['SDNN', 14.2, 'below reference middle band']]
    },
    warnings: ['Descriptive research method only; not medical advice.'],
    provenance: {
      algorithmVersion: '0.1.0',
      algorithmImageDigest: IMAGE.split('@').at(-1),
      datasetSchemaVersion: 'brainstem.personal-resting-hrv-methods/v1',
      generatedAt: '2026-07-28T00:00:00Z',
      candidateManifestSha256: METHODS_CANDIDATE_SHA256,
      referenceSha256: METHODS_REFERENCE_SHA256
    }
  }
}

function sampleEntropyInput(): any {
  return {
    schema: 'brainstem.personal-resting-sample-entropy/v1',
    recordings: [
      {
        recordingType: 'rest',
        durationSeconds: 300,
        rrIntervalsMs: Array.from(
          { length: 300 },
          (_, index) => 990 + 20 * Math.sin(index / 11)
        )
      }
    ]
  }
}

function sleepBaselineInput(): any {
  const rrIntervalsMs = Array(18000).fill(1000)
  return {
    schema: 'brainstem.personal-sleep-baseline/v1',
    policy: 'brainstem.personal-sleep-baseline/latest-7/v1',
    recordings: [
      {
        recordingType: 'sleep',
        durationSeconds: 18000,
        intervalSemantics: 'detector_rr_unclassified',
        allowedUse: 'private_descriptive_self_only',
        quality: {
          observedIntervalCount: rrIntervalsMs.length,
          acceptedIntervalCount: rrIntervalsMs.length,
          acceptedFraction: 1,
          durationCoverageRatio: 1,
          normalToNormalProvenance: 'unverified',
          officialMethodInputCompatible: false
        },
        rrIntervalsMs
      }
    ]
  }
}

function sampleEntropyResult(): any {
  const value = methodsResult()
  value.analysisId = SAMPLE_ENTROPY_ANALYSIS_ID
  value.title = 'Resting rhythm complexity'
  value.metrics = [{ label: 'Sample entropy', value: 1.234, unit: 'unitless' }]
  value.charts = [
    {
      type: 'bar',
      title: 'Resting rhythm complexity',
      x: { label: 'Method', values: ['Sample entropy'] },
      y: { label: 'Value', unit: 'unitless' },
      series: [{ label: 'Result', values: [1.234] }]
    }
  ]
  value.provenance = {
    ...value.provenance,
    datasetSchemaVersion: 'brainstem.personal-resting-sample-entropy/v1',
    candidateManifestSha256: SAMPLE_ENTROPY_CANDIDATE_SHA256,
    referenceSha256: '3'.repeat(64)
  }
  return value
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
  let authorizedChecksum: string
  let completionConnectionFailures: number

  beforeEach(async () => {
    process.env.PERSONAL_INSIGHT_TEST_TOKEN = 'generated-personal-test-token-long-enough'
    process.env.PERSONAL_INSIGHT_BFF_TEST_TOKEN = BFF_TOKEN
    requests = []
    revalidationStatus = 200
    capabilityStatus = 200
    authorizedChecksum = RESULT_CHECKSUM
    completionConnectionFailures = 0
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
          const claimed =
            body.analysisId === METHODS_ANALYSIS_ID
              ? methodsPolicy(crabUrl)
              : policy(crabUrl)
          response.writeHead(200, { 'Content-Type': 'application/json' })
          response.end(
            JSON.stringify({
              result: {
                status: 'claimed',
                analysisId: claimed.analysisId,
                algorithmVersion: claimed.algorithmVersion,
                expiresAt: '2026-07-27T07:05:00Z',
                algorithmImageDigest: IMAGE.split('@').at(-1),
                inputSchema: claimed.inputSchema,
                inputPolicy: claimed.inputPolicy,
                resultSchema: claimed.resultContract,
                resultProfile: claimed.resultProfile,
                candidateManifestSha256: claimed.candidateManifestSha256,
                approvedManifestSha256: claimed.approvedManifestSha256,
                referenceSha256: claimed.referenceSha256,
                evidenceTier: claimed.evidenceTier,
                useClass: claimed.useClass,
                clinicalUse: claimed.clinicalUse,
                maximumRecordings: claimed.maximumRecordings,
                audience: claimed.audience,
                historyId: HISTORY_ID
              }
            })
          )
          return
        }
        if (request.url?.endsWith('/runs/complete')) {
          if (completionConnectionFailures > 0) {
            completionConnectionFailures--
            request.socket.destroy()
            return
          }
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
        if (request.url?.endsWith('/history/revalidate')) {
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
                historyId: HISTORY_ID
              }
            })
          )
          return
        }
        if (
          request.url?.endsWith('/capabilities/consume') &&
          !request.url.includes('/history/')
        ) {
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
                resultSha256: body.action === 'result' ? authorizedChecksum : null
              }
            })
          )
          return
        }
        if (request.url?.endsWith('/history/capabilities/consume')) {
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
                historyId: HISTORY_ID,
                resultSha256: body.action === 'result' ? authorizedChecksum : null
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
    expect(
      await claimPersonalInsightGrant(configured, GRANT, JOB_ID, RUN_ID, environment)
    ).to.equal(HISTORY_ID)
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
    await revalidatePersonalInsightHistory(configured, HISTORY_ID, environment)
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
    expect(
      await consumePersonalInsightHistoryCapability(
        configured,
        CAPABILITY,
        HISTORY_ID,
        'result',
        environment
      )
    ).to.equal(RESULT_CHECKSUM)

    expect(requests.map(({ url }) => url)).to.deep.equal([
      '/api/v1/internal/personal-insights/grants/claim',
      '/api/v1/internal/personal-insights/dataset',
      '/api/v1/internal/personal-insights/runs/complete',
      '/api/v1/internal/personal-insights/runs/revalidate',
      '/api/v1/internal/personal-insights/history/revalidate',
      '/api/v1/internal/personal-insights/capabilities/consume',
      '/api/v1/internal/personal-insights/capabilities/consume',
      '/api/v1/internal/personal-insights/history/capabilities/consume'
    ])
    expect(
      requests.every(
        ({ authorization }) =>
          authorization === 'Bearer generated-personal-test-token-long-enough'
      )
    ).to.equal(true)
    expect(requests[0].body).to.deep.equal({
      analysisId: ANALYSIS_ID,
      grant: GRANT,
      jobId: JOB_ID,
      runId: RUN_ID
    })
    expect(requests[1].headers['x-brainstem-personal-grant']).to.equal(GRANT)
    expect(requests[1].headers['x-ocean-compute-job-id']).to.equal(JOB_ID)
    expect(requests[1].headers['x-brainstem-analysis-id']).to.equal(ANALYSIS_ID)
    expect(requests[4].body).to.deep.equal({
      analysisId: ANALYSIS_ID,
      historyId: HISTORY_ID
    })
    expect(JSON.parse(readFileSync(destination, 'utf8'))).to.deep.equal(input())
    expect(fetched.bytes).to.equal(readFileSync(destination).length)
  })

  it('validates the exact personal input and result profile', () => {
    const configured = policy('https://crab.internal/')
    expect(() =>
      validatePersonalInsightInput(Buffer.from(JSON.stringify(input())), configured)
    ).not.to.throw()
    expect(() =>
      validatePersonalInsightResult(Buffer.from(JSON.stringify(result())), configured)
    ).not.to.throw()

    const wrongInput = { ...input(), participant: 'must-not-enter-compute' }
    expect(() =>
      validatePersonalInsightInput(Buffer.from(JSON.stringify(wrongInput)), configured)
    ).to.throw(PersonalInsightError, 'personal_insight_dataset_invalid')
    const wrongResult = result()
    wrongResult.metrics[0].value = 2
    expect(() =>
      validatePersonalInsightResult(Buffer.from(JSON.stringify(wrongResult)), configured)
    ).to.throw(PersonalInsightError, 'personal_insight_result_invalid')
  })

  it('binds the reviewed methods release and its exact personal contracts', async () => {
    const configured = methodsPolicy(crabUrl)
    expect(
      await claimPersonalInsightGrant(configured, GRANT, JOB_ID, RUN_ID, environment)
    ).to.equal(HISTORY_ID)
    expect(requests[0].body.analysisId).to.equal(METHODS_ANALYSIS_ID)
    expect(() =>
      validatePersonalInsightInput(
        Buffer.from(JSON.stringify(methodsInput())),
        configured
      )
    ).not.to.throw()
    expect(() =>
      validatePersonalInsightResult(
        Buffer.from(JSON.stringify(methodsResult())),
        configured
      )
    ).not.to.throw()

    const identityLeak = { ...methodsInput(), participant: 'must-not-enter-compute' }
    expect(() =>
      validatePersonalInsightInput(Buffer.from(JSON.stringify(identityLeak)), configured)
    ).to.throw(PersonalInsightError, 'personal_insight_dataset_invalid')
    const wrongReference = methodsResult()
    wrongReference.provenance.referenceSha256 = '9'.repeat(64)
    expect(() =>
      validatePersonalInsightResult(
        Buffer.from(JSON.stringify(wrongReference)),
        configured
      )
    ).to.throw(PersonalInsightError, 'personal_insight_result_invalid')
  })

  it('binds the sample entropy release and exact latest-four contract', () => {
    const configured = sampleEntropyPolicy('https://crab.internal/')
    expect(() =>
      validatePersonalInsightInput(
        Buffer.from(JSON.stringify(sampleEntropyInput())),
        configured
      )
    ).not.to.throw()
    expect(() =>
      validatePersonalInsightResult(
        Buffer.from(JSON.stringify(sampleEntropyResult())),
        configured
      )
    ).not.to.throw()

    const tooMany = sampleEntropyInput()
    tooMany.recordings = Array(5).fill(tooMany.recordings[0])
    expect(() =>
      validatePersonalInsightInput(Buffer.from(JSON.stringify(tooMany)), configured)
    ).to.throw(PersonalInsightError, 'personal_insight_dataset_invalid')
  })

  it('binds the sleep baseline release and exact private full-night contract', () => {
    const configured = sleepBaselinePolicy('https://crab.internal/')
    expect(() =>
      validatePersonalInsightInput(
        Buffer.from(JSON.stringify(sleepBaselineInput())),
        configured
      )
    ).not.to.throw()

    const mismatchedQuality = sleepBaselineInput()
    mismatchedQuality.recordings[0].quality.acceptedIntervalCount -= 1
    expect(() =>
      validatePersonalInsightInput(
        Buffer.from(JSON.stringify(mismatchedQuality)),
        configured
      )
    ).to.throw(PersonalInsightError, 'personal_insight_dataset_invalid')
  })

  it('retries only an idempotent completion after a lost connection', async () => {
    completionConnectionFailures = 1
    await completePersonalInsightRun(
      policy(crabUrl),
      GRANT,
      JOB_ID,
      RUN_ID,
      RESULT_CHECKSUM,
      environment
    )
    expect(requests.filter(({ url }) => url.endsWith('/runs/complete')).length).to.equal(
      2
    )
  })

  it('accepts only a bounded immutable image command', () => {
    expect(
      getPersonalInsightImageExecution({
        Entrypoint: ['python', '/app/ocean_entrypoint.py'],
        Cmd: null,
        WorkingDir: '/app'
      })
    ).to.deep.equal({
      command: ['python', '/app/ocean_entrypoint.py'],
      workingDir: '/app'
    })
    expect(() =>
      getPersonalInsightImageExecution({ Entrypoint: [], Cmd: null })
    ).to.throw('personal_insight_image_command_invalid')
    expect(() =>
      getPersonalInsightImageExecution({ Entrypoint: ['bad\0command'] })
    ).to.throw('personal_insight_image_command_invalid')
    expect(() =>
      getPersonalInsightImageExecution({
        Entrypoint: ['python'],
        WorkingDir: 'relative'
      })
    ).to.throw('personal_insight_image_command_invalid')
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
      personalInsightHistoryId: HISTORY_ID,
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
    authorizedChecksum = resultSha256
    const historyStatusCapability = `${CAPABILITY}-history-status`
    expect(
      await engine.getPersonalInsightHistoryStatus(HISTORY_ID, historyStatusCapability)
    ).to.deep.equal({ status: 'complete' })
    const historyResultCapability = `${CAPABILITY}-history-result`
    expect(
      await engine.getPersonalInsightHistoryResult(HISTORY_ID, historyResultCapability)
    ).to.deep.equal({ bytes: resultBytes, checksum: resultSha256 })
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
    await (engine as any).revalidateRetainedPersonalInsightHistory()
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

    const reviewedMethods = methodsPolicy('https://crab.internal/')
    const methodsConfigured = {
      ...configured,
      consumerResultPolicy: {
        mode: 'singleJson',
        maxBytes: 256 * 1024,
        resultContract: 'brainstem.insight-result/v1'
      },
      personalInsight: reviewedMethods
    }
    expect(C2DEnvironmentConfigSchema.safeParse(methodsConfigured).success).to.equal(true)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...methodsConfigured,
        personalInsight: { ...reviewedMethods, referenceSha256: null }
      }).success
    ).to.equal(false)

    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...methodsConfigured,
        personalInsight: sleepBaselinePolicy('https://crab.internal/')
      }).success
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
      personalInsightHistoryId: HISTORY_ID,
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
          startPersonalInsight: (analysisId: string, grant: string) =>
            analysisId === ANALYSIS_ID && grant === GRANT
              ? Promise.resolve({ runId: RUN_ID })
              : Promise.reject(new Error('not_found')),
          getPersonalInsightStatus: () => Promise.resolve({ status: 'complete' }),
          getPersonalInsightHistoryStatus: () => Promise.resolve({ status: 'complete' }),
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
            }),
          getPersonalInsightHistoryResult: () =>
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
      const start = await axios.post(`${base}/start`, {
        analysisId: ANALYSIS_ID,
        grant: GRANT
      })
      expect(start.status).to.equal(202)
      expect(start.data).to.deep.equal({ runId: RUN_ID })
      const status = await axios.post(`${base}/status`, {
        runId: RUN_ID,
        capability: CAPABILITY
      })
      expect(status.data).to.deep.equal({ status: 'complete' })
      const historyStatus = await axios.post(
        `${base.replace('/runs', '/history')}/status`,
        { historyId: HISTORY_ID, capability: CAPABILITY }
      )
      expect(historyStatus.data).to.deep.equal({ status: 'complete' })
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
      const historyResult = await axios.post(
        `${base.replace('/runs', '/history')}/result`,
        { historyId: HISTORY_ID, capability: CAPABILITY }
      )
      expect(historyResult.headers['x-content-sha256']).to.equal(RESULT_CHECKSUM)
      const rejected = await axios.post(
        `${base}/start`,
        {
          analysisId: ANALYSIS_ID,
          grant: GRANT,
          environment: 'caller-controlled'
        },
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
