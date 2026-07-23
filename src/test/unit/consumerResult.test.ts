/* eslint-disable security/detect-non-literal-fs-filename */
import { expect } from 'chai'
import { Readable } from 'stream'
import * as tarStream from 'tar-stream'
import sinon from 'sinon'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'fs'
import os from 'os'
import path from 'path'

import {
  readSingleJsonResultArchive,
  validateConsumerResultContract
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
      billable: true
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
