/* eslint-disable security/detect-non-literal-fs-filename */
import { expect } from 'chai'
import { createHash } from 'crypto'
import { AddressInfo } from 'net'
import { createServer, Server } from 'http'
import { mkdtempSync, readFileSync, rmSync, statSync } from 'fs'
import { tmpdir } from 'os'
import path from 'path'
import {
  assertPrivateDatasetJob,
  downloadPrivateDataset,
  PrivateDatasetError
} from '../../components/c2d/privateDataset.js'
import type { PrivateDatasetPolicy } from '../../@types/C2D/C2D.js'
import type { UrlFileObject } from '../../@types/fileObject.js'

const JOB_ID = 'a'.repeat(64)
const IMAGE = `brainstem/private-rr@sha256:${'b'.repeat(64)}`

describe('Private dataset provisioning', () => {
  let server: Server
  let directory: string
  let destination: string
  let requestCount: number
  let receivedJobId: string
  let receivedAuthorization: string
  let receivedReleaseId: string
  let responseMode: string
  let body: Buffer
  let policy: PrivateDatasetPolicy
  let file: UrlFileObject
  let environment: NodeJS.ProcessEnv

  beforeEach(async () => {
    requestCount = 0
    receivedJobId = ''
    receivedAuthorization = ''
    receivedReleaseId = ''
    responseMode = 'valid'
    body = Buffer.from('{"schema":"brainstem.private-rr-cohort/v1"}')
    server = createServer((request, response) => {
      requestCount += 1
      receivedJobId = String(request.headers['x-ocean-compute-job-id'] ?? '')
      receivedAuthorization = String(request.headers.authorization ?? '')
      receivedReleaseId = String(request.headers['x-brainstem-cohort-release-id'] ?? '')
      if (responseMode === 'redirect') {
        response.writeHead(302, { Location: '/other' })
        response.end()
        return
      }
      if (responseMode === 'failure') {
        response.writeHead(500)
        response.end('private data must not enter the error')
        return
      }
      const checksum = createHash('sha256').update(body).digest('hex')
      const headers: Record<string, string | number> = {
        'Content-Type': responseMode === 'wrong-type' ? 'text/plain' : 'application/json',
        'X-Content-SHA256': responseMode === 'bad-checksum' ? '0'.repeat(64) : checksum
      }
      if (responseMode !== 'no-length') headers['Content-Length'] = body.length
      response.writeHead(200, headers)
      response.end(body)
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address() as AddressInfo
    const url = `http://127.0.0.1:${address.port}/private-dataset`
    directory = mkdtempSync(path.join(tmpdir(), 'private-dataset-test-'))
    destination = path.join(directory, 'dataset.json')
    policy = {
      url,
      maxBytes: 1024,
      approvedAlgorithmImage: IMAGE,
      bearerTokenEnv: 'CRAB_C2D_TEST_TOKEN',
      releaseId: 'c'.repeat(64)
    }
    environment = { CRAB_C2D_TEST_TOKEN: 'generated-test-token-that-is-long-enough' }
    file = {
      type: 'url',
      url,
      method: 'get'
    }
  })

  afterEach(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    )
    rmSync(directory, { recursive: true, force: true })
  })

  async function expectFailure(code: string): Promise<void> {
    try {
      await downloadPrivateDataset(file, destination, JOB_ID, policy, environment)
      expect.fail('expected private dataset provisioning to fail')
    } catch (error) {
      expect(error).to.be.instanceOf(PrivateDatasetError)
      expect((error as Error).message).to.equal(code)
      expect((error as Error).message).not.to.include(policy.url)
      expect((error as Error).message).not.to.include('generated-test-token')
    }
    expect(() => statSync(destination)).to.throw()
    expect(() => statSync(`${destination}.part`)).to.throw()
  }

  it('fetches exactly once with the opaque job ID and verifies the file', async () => {
    const result = await downloadPrivateDataset(
      file,
      destination,
      JOB_ID,
      policy,
      environment
    )

    expect(requestCount).to.equal(1)
    expect(receivedJobId).to.equal(JOB_ID)
    expect(receivedAuthorization).to.equal(
      'Bearer generated-test-token-that-is-long-enough'
    )
    expect(receivedReleaseId).to.equal('c'.repeat(64))
    expect(readFileSync(destination)).to.deep.equal(body)
    expect(statSync(destination).mode & 0o777).to.equal(0o600)
    expect(result.bytes).to.equal(body.length)
    expect(result.checksum).to.equal(createHash('sha256').update(body).digest('hex'))
  })

  it('rejects caller control of the audit-correlation header before fetching', async () => {
    file.headers = {}
    file.headers['x-Ocean-Compute-Job-Id'] = 'caller-controlled'
    await expectFailure('private_dataset_job_header_is_reserved')
    expect(requestCount).to.equal(0)
  })

  it('rejects caller control of the cohort release header before fetching', async () => {
    file.headers = {
      'X-Brainstem-Cohort-Release-Id': 'researcher-controlled'
    }
    await expectFailure('private_dataset_release_header_is_reserved')
    expect(requestCount).to.equal(0)
  })

  it('rejects all caller-supplied headers and missing service credentials', async () => {
    file.headers = { Authorization: 'Bearer caller-controlled' }
    await expectFailure('private_dataset_headers_not_allowed')
    expect(requestCount).to.equal(0)

    delete file.headers
    environment = {}
    await expectFailure('private_dataset_credential_invalid')
    expect(requestCount).to.equal(0)
  })

  it('rejects checksum mismatch and removes the partial file', async () => {
    responseMode = 'bad-checksum'
    await expectFailure('private_dataset_checksum_mismatch')
    expect(requestCount).to.equal(1)
  })

  it('rejects a missing length before accepting a chunked body', async () => {
    responseMode = 'no-length'
    await expectFailure('private_dataset_content_length_invalid')
    expect(requestCount).to.equal(1)
  })

  it('rejects an oversized declared body', async () => {
    policy.maxBytes = body.length - 1
    await expectFailure('private_dataset_too_large')
    expect(requestCount).to.equal(1)
  })

  it('rejects redirects, non-success responses, and wrong media types safely', async () => {
    responseMode = 'redirect'
    await expectFailure('private_dataset_fetch_failed')

    responseMode = 'failure'
    await expectFailure('private_dataset_fetch_failed')

    responseMode = 'wrong-type'
    await expectFailure('private_dataset_content_type_invalid')
    expect(requestCount).to.equal(3)
  })

  it('rejects URL drift before making a request', async () => {
    file.url = `${policy.url}?researcherFilter=anything`
    await expectFailure('private_dataset_url_not_allowed')
    expect(requestCount).to.equal(0)
  })

  it('denies an unapproved image before provisioning', () => {
    expect(() => assertPrivateDatasetJob(policy, IMAGE, 1)).not.to.throw()
    expect(() =>
      assertPrivateDatasetJob(policy, 'brainstem/private-rr:latest', 1)
    ).to.throw(PrivateDatasetError, 'private_dataset_algorithm_not_approved')
    expect(() => assertPrivateDatasetJob(policy, IMAGE, 2)).to.throw(
      PrivateDatasetError,
      'private_dataset_requires_one_asset'
    )
  })
})
