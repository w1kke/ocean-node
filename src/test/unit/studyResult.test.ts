import { expect } from 'chai'
import { createHash } from 'crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'fs'
import { createServer, Server } from 'http'
import { AddressInfo } from 'net'
import { tmpdir } from 'os'
import { join } from 'path'
import type { DBComputeJob, PrivateDatasetPolicy } from '../../@types/C2D/C2D.js'
import {
  commitStudyResult,
  StudyResultCommitError
} from '../../components/c2d/studyResult.js'

const DIGEST = `sha256:${'d'.repeat(64)}`

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.keys(value as Record<string, unknown>)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`
      )
      .join(',')}}`
  }
  return JSON.stringify(value) ?? 'null'
}

describe('Study result commit', () => {
  let server: Server
  let requests = 0
  let authorization = ''
  let policy: PrivateDatasetPolicy
  let result: Record<string, unknown>
  let job: DBComputeJob
  let directory: string
  let resultPath: string

  beforeEach(async () => {
    requests = 0
    authorization = ''
    directory = mkdtempSync(join(tmpdir(), 'brainstem-study-result-'))
    mkdirSync(join(directory, 'outputs'))
    resultPath = join(directory, 'outputs', 'result.json')
    result = {
      schema: 'brainstem.c2d-result/v1',
      status: 'complete',
      title: 'Full-night signal compatibility',
      summary: 'The reviewed group met the signal-quality contract.',
      metrics: [{ label: 'Median recording duration', value: 5.1, unit: 'hours' }],
      charts: [],
      table: null,
      warnings: ['Not apnea screening or diagnosis.'],
      provenance: {
        algorithmVersion: '0.1.0',
        algorithmImageDigest: DIGEST,
        datasetSchemaVersion: 'brainstem.full-night-rr-cohort/v1',
        generatedAt: '2026-08-05T00:03:00Z'
      }
    }
    server = createServer((request, response) => {
      requests += 1
      authorization = String(request.headers.authorization ?? '')
      response.writeHead(201, { 'Content-Type': 'application/json' })
      response.end(
        JSON.stringify({
          result: {
            proposalId: 'study_a',
            revisionId: 'revision_b',
            revisionSha256: 'e'.repeat(64),
            resultSha256: createHash('sha256').update(canonical(result)).digest('hex'),
            algorithmImageDigest: DIGEST
          }
        })
      )
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/dataset`
    policy = {
      analysisId: 'brainstem.full-night-rr-signal-compatibility/v1',
      url,
      maxBytes: 1024,
      approvedAlgorithmImage: `brainstem/full-night@${DIGEST}`,
      bearerTokenEnv: 'CRAB_DATASET_TOKEN',
      releaseId: 'f'.repeat(64),
      allowInsecureLocalProof: true,
      study: {
        proposalId: 'study_a',
        revisionId: 'revision_b',
        revisionSha256: 'e'.repeat(64),
        resultBearerTokenEnv: 'CRAB_RESULT_TOKEN'
      }
    }
    job = {
      jobIdHash: `0x${'a'.repeat(64)}`,
      privateInputChecksum: 'b'.repeat(64),
      privateSourceSnapshotSha256: 'c'.repeat(64),
      resultValidation: {
        contract: 'brainstem.c2d-result/v1',
        status: 'complete',
        billable: true,
        algorithmVersion: '0.1.0',
        algorithmImageDigest: DIGEST,
        datasetSchemaVersion: 'brainstem.full-night-rr-cohort/v1'
      }
    } as DBComputeJob
  })

  afterEach(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    )
    rmSync(directory, { recursive: true, force: true })
  })

  it('commits one bounded receipt with a separate service credential', async () => {
    await commitStudyResult(
      job,
      Buffer.from(JSON.stringify(result)),
      policy,
      resultPath,
      {
        CRAB_DATASET_TOKEN: 'generated-dataset-token-that-is-long-enough',
        CRAB_RESULT_TOKEN: 'generated-result-token-that-is-long-enough'
      }
    )
    expect(requests).to.equal(1)
    expect(authorization).to.equal('Bearer generated-result-token-that-is-long-enough')
    expect(readFileSync(resultPath, 'utf8')).to.equal(JSON.stringify(result))
  })

  it('commits a valid result larger than the generic request limit', async () => {
    result.summary = 'x'.repeat(40 * 1024)
    await commitStudyResult(
      job,
      Buffer.from(JSON.stringify(result)),
      policy,
      resultPath,
      {
        CRAB_DATASET_TOKEN: 'generated-dataset-token-that-is-long-enough',
        CRAB_RESULT_TOKEN: 'generated-result-token-that-is-long-enough'
      }
    )
    expect(requests).to.equal(1)
  })

  it('rejects study dataset provenance drift before contact', async () => {
    ;(result.provenance as Record<string, unknown>).datasetSchemaVersion =
      'brainstem.private-rr-cohort/v1'
    try {
      await commitStudyResult(
        job,
        Buffer.from(JSON.stringify(result)),
        policy,
        resultPath,
        {
          CRAB_DATASET_TOKEN: 'generated-dataset-token-that-is-long-enough',
          CRAB_RESULT_TOKEN: 'generated-result-token-that-is-long-enough'
        }
      )
      expect.fail('expected the commit to fail')
    } catch (error) {
      expect(error).to.be.instanceOf(StudyResultCommitError)
    }
    expect(requests).to.equal(0)
    expect(existsSync(resultPath)).to.equal(false)
  })

  it('fails before contact when the export snapshot is absent', async () => {
    delete job.privateSourceSnapshotSha256
    try {
      await commitStudyResult(
        job,
        Buffer.from(JSON.stringify(result)),
        policy,
        resultPath,
        {
          CRAB_DATASET_TOKEN: 'generated-dataset-token-that-is-long-enough',
          CRAB_RESULT_TOKEN: 'generated-result-token-that-is-long-enough'
        }
      )
      expect.fail('expected the commit to fail')
    } catch (error) {
      expect(error).to.be.instanceOf(StudyResultCommitError)
    }
    expect(requests).to.equal(0)
  })
})
