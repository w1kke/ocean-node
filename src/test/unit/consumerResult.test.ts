/* eslint-disable security/detect-non-literal-fs-filename */
import { expect } from 'chai'
import { createHash } from 'crypto'
import { Readable } from 'stream'
import * as tarStream from 'tar-stream'
import sinon from 'sinon'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'fs'
import os from 'os'
import path from 'path'

import {
  readSingleJsonResultArchive,
  validateConsumerResultContract,
  validateReviewedInsightResult,
  validateSleepReliabilityResult
} from '../../components/c2d/consumerResult.js'
import {
  C2DStatusNumber,
  C2DStatusText,
  type DBComputeJob
} from '../../@types/C2D/C2D.js'
import { Storage } from '../../components/storage/index.js'

type ArchiveEntry = {
  name: string
  body?: Buffer | string
  type?: 'file' | 'symlink' | 'directory'
  linkname?: string
}

async function makeArchive(entries: ArchiveEntry[]): Promise<Buffer> {
  const pack = tarStream.pack()
  const chunks: Buffer[] = []
  const complete = (async () => {
    for await (const chunk of pack) chunks.push(Buffer.from(chunk))
  })()

  for (const entry of entries) {
    const body = Buffer.isBuffer(entry.body) ? entry.body : Buffer.from(entry.body ?? '')
    pack.entry(
      {
        name: entry.name,
        type: entry.type ?? 'file',
        linkname: entry.linkname,
        size: entry.type && entry.type !== 'file' ? 0 : body.length
      },
      entry.type && entry.type !== 'file' ? undefined : body
    )
  }
  pack.finalize()
  await complete
  return Buffer.concat(chunks)
}

async function expectRejected(archive: Buffer, message: string, maxBytes = 1024) {
  let failure: Error = null
  try {
    await readSingleJsonResultArchive(Readable.from([archive]), maxBytes)
  } catch (error) {
    failure = error as Error
  }
  expect(failure?.message.toLowerCase()).to.include(message.toLowerCase())
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (value !== null && typeof value === 'object') {
    return `{${Object.entries(value)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(',')}}`
  }
  return JSON.stringify(value)
}

describe('single JSON consumer result', () => {
  afterEach(() => sinon.restore())

  it('returns the original bytes for one bounded JSON object', async () => {
    const body = Buffer.from('{"ok":true,"value":42}')
    const archive = await makeArchive([{ name: 'result.json', body }])

    const result = await readSingleJsonResultArchive(Readable.from([archive]), 1024)

    expect(result.equals(body)).to.equal(true)
  })

  it('rejects empty, extra, duplicate, nested, and linked entries', async () => {
    await expectRejected(await makeArchive([]), 'exactly one')
    await expectRejected(
      await makeArchive([
        { name: 'result.json', body: '{}' },
        { name: 'notes.txt', body: 'private' }
      ]),
      'extra entries'
    )
    await expectRejected(
      await makeArchive([
        { name: 'result.json', body: '{}' },
        { name: 'result.json', body: '{}' }
      ]),
      'extra entries'
    )
    await expectRejected(
      await makeArchive([{ name: 'outputs/result.json', body: '{}' }]),
      'only result.json'
    )
    await expectRejected(
      await makeArchive([
        { name: 'result.json', type: 'symlink', linkname: '/private/source' }
      ]),
      'regular file'
    )
  })

  it('rejects invalid UTF-8, invalid JSON, and non-object JSON', async () => {
    await expectRejected(
      await makeArchive([{ name: 'result.json', body: Buffer.from([0xc3, 0x28]) }]),
      'valid UTF-8'
    )
    await expectRejected(
      await makeArchive([{ name: 'result.json', body: '{broken' }]),
      'valid JSON'
    )
    await expectRejected(
      await makeArchive([{ name: 'result.json', body: '[1,2,3]' }]),
      'JSON object'
    )
  })

  it('rejects content over the configured limit and truncated archives', async () => {
    await expectRejected(
      await makeArchive([{ name: 'result.json', body: '{"value":"too large"}' }]),
      'size limit',
      4
    )
    const archive = await makeArchive([{ name: 'result.json', body: '{}' }])
    await expectRejected(archive.subarray(0, 600), 'unexpected end of data')
  })

  it('classifies only contract-valid aggregate and suppressed results as billable', () => {
    const base: any = {
      schema: 'brainstem.c2d-result/v1',
      status: 'complete',
      title: 'Resting R-R cohort summary',
      summary: 'Aggregate participant-weighted result.',
      metrics: [{ label: 'Median R-R', value: 810, unit: 'ms' }],
      charts: [],
      table: null,
      warnings: [],
      provenance: {
        algorithmVersion: '1.0.0',
        algorithmImageDigest: `sha256:${'a'.repeat(64)}`,
        datasetSchemaVersion: 'brainstem.private-rr-cohort/v1',
        generatedAt: '2026-07-23T00:00:00Z'
      }
    }
    const policy = {
      mode: 'singleJson' as const,
      maxBytes: 262144,
      resultContract: 'brainstem.c2d-result/v1' as const
    }

    expect(
      validateConsumerResultContract(Buffer.from(JSON.stringify(base)), policy)
    ).to.deep.equal({
      contract: 'brainstem.c2d-result/v1',
      status: 'complete',
      billable: true,
      algorithmVersion: '1.0.0',
      algorithmImageDigest: `sha256:${'a'.repeat(64)}`,
      datasetSchemaVersion: 'brainstem.private-rr-cohort/v1'
    })
    const suppressed = {
      ...base,
      status: 'insufficient_data',
      metrics: [],
      summary: 'The eligible cohort is below the disclosure threshold.'
    }
    expect(
      validateConsumerResultContract(Buffer.from(JSON.stringify(suppressed)), policy)
        ?.billable
    ).to.equal(true)
    const failed = { ...suppressed, status: 'failed' }
    expect(
      validateConsumerResultContract(Buffer.from(JSON.stringify(failed)), policy)
        ?.billable
    ).to.equal(false)

    for (const invalid of [
      { ...base, participantId: 'must-not-leak' },
      { ...base, summary: 'See https://private.example/result' },
      { ...base, status: 'insufficient_data', metrics: base.metrics },
      { ...base, metrics: [], charts: [], table: null }
    ]) {
      expect(() =>
        validateConsumerResultContract(Buffer.from(JSON.stringify(invalid)), policy)
      ).to.throw('does not match')
    }
    expect(() =>
      validateConsumerResultContract(
        Buffer.from(JSON.stringify(base)),
        policy,
        `sha256:${'b'.repeat(64)}`
      )
    ).to.throw('does not match execution')
  })

  it('binds a reviewed cohort result to its immutable evidence policy', () => {
    const candidate = '15dbf8544c87d81c06f5e512b00e9fe39dd6431dd1a4079a97da68a3f92721c1'
    const image = `sha256:${'a'.repeat(64)}`
    const result: any = {
      schema: 'brainstem.insight-result/v1',
      analysisId: 'brainstem.resting-hrv-methods/v1',
      scope: 'cohort',
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
      summary: 'Disclosure-protected descriptive group result.',
      metrics: [{ label: 'SDNN', value: 24.2, unit: 'ms' }],
      charts: [],
      table: null,
      warnings: ['Descriptive research method only; not medical advice.'],
      provenance: {
        algorithmVersion: '0.1.0',
        algorithmImageDigest: image,
        datasetSchemaVersion: 'brainstem.resting-hrv-methods-cohort/v1',
        generatedAt: '2026-07-28T00:00:00Z',
        candidateManifestSha256: candidate,
        referenceSha256: null
      }
    }
    const expected = {
      analysisId: 'brainstem.resting-hrv-methods/v1',
      scope: 'cohort' as const,
      algorithmVersion: '0.1.0',
      algorithmImageDigest: image,
      inputSchema: 'brainstem.resting-hrv-methods-cohort/v1',
      candidateManifestSha256: candidate,
      referenceSha256: null as null,
      evidenceTier: 'E2_brainstem_compatible_exploratory',
      useClass: 'methods_only',
      clinicalUse: 'prohibited' as const
    }
    expect(() =>
      validateReviewedInsightResult(Buffer.from(JSON.stringify(result)), expected)
    ).not.to.throw()
    result.scope = 'personal'
    expect(() =>
      validateReviewedInsightResult(Buffer.from(JSON.stringify(result)), expected)
    ).to.throw('reviewed Insight policy')
  })

  it('validates and hashes the exact sleep reliability reference', () => {
    const image = `sha256:${'a'.repeat(64)}`
    const estimate = (unit: 'hours' | 'bpm') => ({
      unit,
      p10: 1,
      p25: 2,
      p50: 3,
      p75: 4,
      p90: 5,
      icc11: 0.8,
      icc11Ci95: [0.7, 0.9],
      meanReliabilityByNights: Array.from({ length: 7 }, (_, index) => ({
        nights: index + 1,
        estimate: 0.8,
        ci95: [0.7, 0.9]
      })),
      minimumNightsForLowerCi80: 3,
      medianWithinPersonCvPercent: 4,
      medianWithinPersonCvPercentCi95: [3, 5]
    })
    const referenceValue: any = {
      schema: 'brainstem.sleep-reliability-reference/v1',
      version: 'generated-review-candidate-v1',
      analysisId: 'brainstem.sleep-baseline/v2',
      sourceType: 'generated_fixture',
      sourceReleaseSha256: '1'.repeat(64),
      sourceSnapshotSha256: '2'.repeat(64),
      inclusionContract: 'brainstem.full-night-nightly-features/exact-distinct-7/v1',
      algorithmVersion: '0.3.0',
      algorithmImageDigest: image,
      candidateManifestSha256:
        'b9bcc30891ffa7368f6169947b9aea9e2bb968a4a4db56287bd1ffde98d94073',
      referenceYear: 2026,
      minimumParticipants: 20,
      ageBands: ['under_30', '30_44', '45_59', '60_plus'],
      reliability: {
        durationHours: estimate('hours'),
        sleepingRateBpm: estimate('bpm')
      },
      scopes: [
        {
          scopeId: '3'.repeat(64),
          dimensions: [],
          participantCountBand: '20 to 49',
          bands: {
            durationHours: [2, 4],
            sleepingRateBpm: [50, 70],
            acceptedPercent: [95, 100]
          }
        }
      ]
    }
    const reference = {
      ...referenceValue,
      sha256: createHash('sha256')
        .update(`${canonicalJson(referenceValue)}\n`)
        .digest('hex')
    }
    const result: any = {
      schema: 'brainstem.c2d-result/v1',
      status: 'complete',
      title: 'Sleep recording reliability benchmark',
      summary: 'Generated reliability result.',
      metrics: [{ label: 'Reliability', value: 0.8, unit: 'ICC' }],
      charts: [],
      table: null,
      warnings: [],
      provenance: {
        analysisId: 'brainstem.sleep-reliability-benchmark/v1',
        algorithmVersion: '0.3.0',
        algorithmImageDigest: image,
        candidateManifestSha256:
          'b9bcc30891ffa7368f6169947b9aea9e2bb968a4a4db56287bd1ffde98d94073',
        datasetSchemaVersion: 'brainstem.sleep-nightly-features-cohort/v1',
        selectorPolicy: 'brainstem.full-night-nightly-features/exact-distinct-7/v1',
        generatedAt: '2026-08-31T00:00:00Z',
        estimator: 'ICC(1,1) balanced one-way random-effects absolute agreement',
        bootstrap: '10000 deterministic participant-level resamples',
        referenceSha256: reference.sha256
      },
      reference
    }
    const bytes = Buffer.from(JSON.stringify(result))
    expect(() => validateSleepReliabilityResult(bytes, image)).not.to.throw()
    expect(
      validateConsumerResultContract(bytes, {
        mode: 'singleJson',
        maxBytes: 262144,
        resultContract: 'brainstem.c2d-result/v1'
      })?.status
    ).to.equal('complete')

    result.reference.reliability.durationHours.p50 = 3.5
    expect(() =>
      validateSleepReliabilityResult(Buffer.from(JSON.stringify(result)), image)
    ).to.throw('reference digest')
  })

  it('publishes only validated bytes to local or remote storage', async () => {
    if (!process.env.PRIVATE_KEY) process.env.PRIVATE_KEY = `0x${'11'.repeat(32)}`
    const { C2DEngineDocker } =
      await import('../../components/c2d/compute_engine_docker.js')
    const tempFolder = mkdtempSync(path.join(os.tmpdir(), 'ocean-result-publish-')) + '/'
    const body = Buffer.from('{"approved":true}')
    const validArchive = await makeArchive([{ name: 'result.json', body }])
    const invalidArchive = await makeArchive([
      { name: 'result.json', body },
      { name: 'private.log', body: 'must not publish' }
    ])
    const archives = new Map([
      ['local-algoritm', validArchive],
      ['remote-algoritm', validArchive],
      ['invalid-algoritm', invalidArchive]
    ])
    const db = { updateJob: sinon.stub().resolves() } as any
    const keyManager = {
      decrypt: sinon
        .stub()
        .resolves(Buffer.from(JSON.stringify({ remoteStorage: { type: 'test' } })))
    } as any
    const cluster = {
      type: 2,
      hash: 'publish-test',
      tempFolder,
      connection: {}
    } as any
    const engine = new C2DEngineDocker(cluster, db, {} as any, keyManager, {} as any)
    sinon.stub(engine, 'getComputeEnvironments').resolves([
      {
        id: 'strict-env',
        consumerResultPolicy: { mode: 'singleJson', maxBytes: 1024 }
      } as any
    ])
    ;(engine as any).cleanupJob = sinon.stub().resolves()
    ;(engine as any).docker = {
      getContainer: (name: string) => ({
        inspect: sinon.stub().resolves({
          State: { OOMKilled: false, ExitCode: 0 }
        }),
        getArchive: sinon
          .stub()
          .callsFake(() => Promise.resolve(Readable.from([archives.get(name)])))
      })
    }
    let uploaded = Buffer.alloc(0)
    let uploadedName = ''
    sinon.stub(Storage, 'getStorageClass').returns({
      hasUpload: true,
      upload: async (name: string, stream: Readable) => {
        uploadedName = name
        const chunks = []
        for await (const chunk of stream) chunks.push(Buffer.from(chunk))
        uploaded = Buffer.concat(chunks)
      }
    } as any)

    const makePublishingJob = (jobId: string, output: string | null = null) =>
      ({
        jobId,
        environment: 'strict-env',
        status: C2DStatusNumber.PublishingResults,
        statusText: C2DStatusText.PublishingResults,
        terminationDetails: { OOMKilled: null, exitCode: null },
        isRunning: false,
        dateFinished: '',
        output
      }) as DBComputeJob

    try {
      for (const jobId of ['local', 'remote', 'invalid']) {
        mkdirSync(path.join(engine.getStoragePath(), jobId, 'data', 'outputs'), {
          recursive: true
        })
      }
      const local = makePublishingJob('local')
      await (engine as any).processJob(local)
      const localPath = path.join(
        engine.getStoragePath(),
        'local',
        'data',
        'outputs',
        'result.json'
      )
      expect(readFileSync(localPath).equals(body)).to.equal(true)
      expect(existsSync(`${localPath}.tmp`)).to.equal(false)

      const remote = makePublishingJob('remote', Buffer.from('encrypted').toString('hex'))
      await (engine as any).processJob(remote)
      expect(uploaded.equals(body)).to.equal(true)
      expect(uploadedName).to.equal('result-publish-test-remote.json')

      const invalid = makePublishingJob('invalid')
      await (engine as any).processJob(invalid)
      expect(invalid.status).to.equal(C2DStatusNumber.ResultsFetchFailed)
      expect(
        existsSync(
          path.join(engine.getStoragePath(), 'invalid', 'data', 'outputs', 'result.json')
        )
      ).to.equal(false)
    } finally {
      rmSync(tempFolder, { recursive: true, force: true })
    }
  })
})
