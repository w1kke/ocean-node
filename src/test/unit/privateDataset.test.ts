/* eslint-disable security/detect-non-literal-fs-filename */
import { expect } from 'chai'
import { createHash } from 'crypto'
import { AddressInfo } from 'net'
import { createServer, Server } from 'http'
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync
} from 'fs'
import { tmpdir } from 'os'
import path from 'path'
import {
  assertPrivateDatasetConfiguration,
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
  let receivedAnalysisId: string
  let receivedStudyProposalId: string
  let receivedStudyRevisionId: string
  let receivedStudyRevisionSha256: string
  let receivedStudyDataPermitId: string
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
    receivedAnalysisId = ''
    receivedStudyProposalId = ''
    receivedStudyRevisionId = ''
    receivedStudyRevisionSha256 = ''
    receivedStudyDataPermitId = ''
    responseMode = 'valid'
    body = Buffer.from('{"schema":"brainstem.private-rr-cohort/v1"}')
    server = createServer((request, response) => {
      requestCount += 1
      receivedJobId = String(request.headers['x-ocean-compute-job-id'] ?? '')
      receivedAuthorization = String(request.headers.authorization ?? '')
      receivedReleaseId = String(request.headers['x-brainstem-cohort-release-id'] ?? '')
      receivedAnalysisId = String(request.headers['x-brainstem-analysis-id'] ?? '')
      receivedStudyProposalId = String(
        request.headers['x-brainstem-study-proposal-id'] ?? ''
      )
      receivedStudyRevisionId = String(
        request.headers['x-brainstem-study-revision-id'] ?? ''
      )
      receivedStudyRevisionSha256 = String(
        request.headers['x-brainstem-study-revision-sha256'] ?? ''
      )
      receivedStudyDataPermitId = String(
        request.headers['x-brainstem-study-data-permit-id'] ?? ''
      )
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
        'X-Content-SHA256': responseMode === 'bad-checksum' ? '0'.repeat(64) : checksum,
        ...(responseMode === 'no-snapshot'
          ? {}
          : { 'X-Brainstem-Source-Snapshot-SHA256': 'e'.repeat(64) })
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
      analysisId: 'brainstem.resting-rr-cohort-summary/v1',
      url,
      maxBytes: 1024,
      approvedAlgorithmImage: IMAGE,
      bearerTokenEnv: 'CRAB_C2D_TEST_TOKEN',
      releaseId: 'c'.repeat(64),
      allowInsecureLocalProof: true
    }
    environment = {
      CRAB_C2D_TEST_TOKEN: 'generated-test-token-that-is-long-enough',
      STUDY_RESULT_TEST_TOKEN: 'generated-result-token-that-is-long-enough'
    }
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
    expect(receivedAnalysisId).to.equal('brainstem.resting-rr-cohort-summary/v1')
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

  it('rejects caller control of the analysis header before fetching', async () => {
    file.headers = {
      'X-Brainstem-Analysis-Id': 'researcher-controlled'
    }
    await expectFailure('private_dataset_analysis_header_is_reserved')
    expect(requestCount).to.equal(0)
  })

  it('binds a reviewed full-night study revision and validates its cohort', async () => {
    policy = {
      ...policy,
      analysisId: 'brainstem.full-night-rr-signal-compatibility/v1',
      maxBytes: 16 * 1024 * 1024,
      study: {
        proposalId: 'study_a',
        revisionId: 'revision_b',
        revisionSha256: 'd'.repeat(64),
        dataPermitId: `data_permit_${'e'.repeat(32)}`,
        resultBearerTokenEnv: 'STUDY_RESULT_TEST_TOKEN'
      }
    }
    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.full-night-rr-cohort/v1',
        policy: 'brainstem.full-night-rr-signal-compatibility/v1',
        participants: Array.from({ length: 20 }, (_, index) => ({
          subjectId: (index + 1).toString(16).padStart(64, '0'),
          recordings: [
            {
              recordingType: 'sleep',
              durationSeconds: 18000,
              intervalSemantics: 'detector_rr_unclassified',
              allowedUse: 'aggregate_method_compatibility_only',
              quality: {
                observedIntervalCount: 9000,
                acceptedIntervalCount: 9000,
                acceptedFraction: 1,
                durationCoverageRatio: 1,
                normalToNormalProvenance: 'unverified',
                officialMethodInputCompatible: false
              },
              rrIntervalsMs: Array(9000).fill(2000)
            }
          ]
        }))
      })
    )

    const downloaded = await downloadPrivateDataset(
      file,
      destination,
      JOB_ID,
      policy,
      environment
    )

    expect(receivedStudyProposalId).to.equal('study_a')
    expect(receivedStudyRevisionId).to.equal('revision_b')
    expect(receivedStudyRevisionSha256).to.equal('d'.repeat(64))
    expect(receivedStudyDataPermitId).to.equal(`data_permit_${'e'.repeat(32)}`)
    expect(downloaded.sourceSnapshotSha256).to.equal('e'.repeat(64))

    const fractionalDuration = JSON.parse(body.toString())
    for (const participant of fractionalDuration.participants) {
      participant.recordings[0].quality.durationCoverageRatio = Number(
        (18000 / 18000.5).toFixed(6)
      )
    }
    body = Buffer.from(JSON.stringify(fractionalDuration))
    await downloadPrivateDataset(
      file,
      `${destination}.fractional`,
      JOB_ID,
      policy,
      environment
    )

    fractionalDuration.participants = Array.from({ length: 101 }, (_, index) => ({
      ...fractionalDuration.participants[0],
      subjectId: (index + 1).toString(16).padStart(64, '0')
    }))
    body = Buffer.from(JSON.stringify(fractionalDuration))
    rmSync(destination)
    await expectFailure('private_dataset_contract_invalid')
  })

  it('rejects caller control of study binding headers before fetching', async () => {
    file.headers = { 'X-Brainstem-Study-Proposal-Id': 'study_a' }
    await expectFailure('private_dataset_study_header_is_reserved')
    expect(requestCount).to.equal(0)

    file.headers = {
      'X-Brainstem-Study-Data-Permit-Id': `data_permit_${'f'.repeat(32)}`
    }
    await expectFailure('private_dataset_study_header_is_reserved')
    expect(requestCount).to.equal(0)
  })

  it('requires a source snapshot for reviewed study inputs', async () => {
    policy = {
      ...policy,
      analysisId: 'brainstem.full-night-rr-signal-compatibility/v1',
      study: {
        proposalId: 'study_a',
        revisionId: 'revision_b',
        revisionSha256: 'd'.repeat(64),
        dataPermitId: `data_permit_${'e'.repeat(32)}`,
        resultBearerTokenEnv: 'STUDY_RESULT_TEST_TOKEN'
      }
    }
    responseMode = 'no-snapshot'
    await expectFailure('private_dataset_source_snapshot_invalid')
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

  it('rejects a missing or unsafe size limit before fetching', async () => {
    policy.maxBytes = 0
    await expectFailure('private_dataset_size_limit_invalid')
    expect(requestCount).to.equal(0)
    expect(() => assertPrivateDatasetConfiguration(policy, environment)).to.throw(
      PrivateDatasetError,
      'private_dataset_size_limit_invalid'
    )
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
    expect(() => assertPrivateDatasetJob(policy, IMAGE, 1, true)).to.throw(
      PrivateDatasetError,
      'private_dataset_remote_output_not_allowed'
    )
  })

  it('accepts only the exact reviewed cohort contract', async () => {
    policy = {
      ...policy,
      maxBytes: 64 * 1024,
      analysisId: 'brainstem.resting-hrv-methods/v1',
      paperInsight: {
        algorithmVersion: '0.1.0',
        inputSchema: 'brainstem.resting-hrv-methods-cohort/v1',
        candidateManifestSha256:
          '15dbf8544c87d81c06f5e512b00e9fe39dd6431dd1a4079a97da68a3f92721c1',
        approvedManifestSha256: 'd'.repeat(64),
        referenceSha256: 'e'.repeat(64),
        evidenceTier: 'E2_brainstem_compatible_exploratory',
        useClass: 'methods_only',
        clinicalUse: 'prohibited'
      }
    }
    expect(() =>
      assertPrivateDatasetConfiguration(
        {
          ...policy,
          study: {
            proposalId: 'study_a',
            revisionId: 'revision_b',
            revisionSha256: 'd'.repeat(64),
            dataPermitId: `data_permit_${'e'.repeat(32)}`,
            resultBearerTokenEnv: 'STUDY_RESULT_TEST_TOKEN'
          }
        },
        environment
      )
    ).to.throw(PrivateDatasetError, 'private_dataset_policy_invalid')
    const intervals = Array.from({ length: 330 }, (_, index) => 900 + (index % 7))
    const participants = Array.from({ length: 20 }, (_, index) => ({
      subjectId: (index + 1).toString(16).padStart(64, '0'),
      recordings: [
        {
          recordingType: 'rest',
          durationSeconds: 300,
          rrIntervalsMs: intervals
        }
      ]
    }))
    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.resting-hrv-methods-cohort/v1',
        participants
      })
    )

    await downloadPrivateDataset(file, destination, JOB_ID, policy, environment)
    expect(receivedAnalysisId).to.equal('brainstem.resting-hrv-methods/v1')
    rmSync(destination)

    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.resting-hrv-methods-cohort/v1',
        participants: participants.slice(0, 19)
      })
    )
    await expectFailure('private_dataset_contract_invalid')

    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.resting-hrv-methods-cohort/v1',
        participants: [],
        participantWallet: 'must-not-enter-compute'
      })
    )
    await expectFailure('private_dataset_contract_invalid')
  })

  it('accepts only the exact sample entropy cohort contract', async () => {
    policy = {
      ...policy,
      maxBytes: 64 * 1024,
      analysisId: 'brainstem.resting-rr-sample-entropy/v1',
      paperInsight: {
        algorithmVersion: '0.1.0',
        inputSchema: 'brainstem.resting-sample-entropy-cohort/v1',
        candidateManifestSha256:
          '65002ab13f02f812c611085c0295b81dc90ec7ffacc79f9ff4927e81e9070bdd',
        approvedManifestSha256: 'd'.repeat(64),
        referenceSha256: 'e'.repeat(64),
        evidenceTier: 'E2_brainstem_compatible_exploratory',
        useClass: 'methods_only',
        clinicalUse: 'prohibited'
      }
    }
    const intervals = Array.from({ length: 300 }, (_, index) => 990 + (index % 11))
    const participants = Array.from({ length: 20 }, (_, index) => ({
      subjectId: (index + 1).toString(16).padStart(64, '0'),
      recordings: [
        {
          recordingType: 'rest',
          durationSeconds: 300,
          rrIntervalsMs: intervals
        }
      ]
    }))
    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.resting-sample-entropy-cohort/v1',
        participants
      })
    )

    await downloadPrivateDataset(file, destination, JOB_ID, policy, environment)
    expect(receivedAnalysisId).to.equal('brainstem.resting-rr-sample-entropy/v1')
    rmSync(destination)

    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.resting-sample-entropy-cohort/v1',
        participants: [
          {
            subjectId: '1'.repeat(64),
            recordings: [
              {
                recordingType: 'rest',
                durationSeconds: 300,
                rrIntervalsMs: intervals
              },
              {
                recordingType: 'rest',
                durationSeconds: 300,
                rrIntervalsMs: intervals
              }
            ]
          }
        ]
      })
    )
    await expectFailure('private_dataset_contract_invalid')
  })

  it('rejects remote plaintext and remote HTTPS without mTLS', () => {
    expect(() =>
      assertPrivateDatasetConfiguration(
        {
          ...policy,
          url: 'http://crab.example.com/api/v1/internal/c2d/rr-cohort'
        },
        environment
      )
    ).to.throw(PrivateDatasetError, 'private_dataset_transport_invalid')
    expect(() =>
      assertPrivateDatasetConfiguration(
        { ...policy, allowInsecureLocalProof: false },
        environment
      )
    ).to.throw(PrivateDatasetError, 'private_dataset_transport_invalid')
    expect(() =>
      assertPrivateDatasetConfiguration(
        {
          ...policy,
          url: 'https://crab.example.com/api/v1/internal/c2d/rr-cohort'
        },
        environment
      )
    ).to.throw(PrivateDatasetError, 'private_dataset_transport_invalid')
  })

  it('fails closed on unsafe mTLS identity and key material', () => {
    const caFile = path.join(directory, 'ca.pem')
    const certificateFile = path.join(directory, 'client.pem')
    const keyFile = path.join(directory, 'client-key.pem')
    writeFileSync(caFile, 'generated test CA', { mode: 0o644 })
    writeFileSync(certificateFile, 'generated test certificate', { mode: 0o644 })
    writeFileSync(keyFile, 'generated test key', { mode: 0o600 })
    const tlsPolicy: PrivateDatasetPolicy = {
      ...policy,
      url: 'https://crab-export.internal/api/v1/internal/c2d/rr-cohort',
      tls: {
        caFile,
        clientCertificateFile: certificateFile,
        clientKeyFile: keyFile,
        serverName: 'crab-export.internal'
      }
    }

    expect(() => assertPrivateDatasetConfiguration(tlsPolicy, environment)).not.to.throw()

    tlsPolicy.tls!.serverName = 'other.internal'
    expect(() => assertPrivateDatasetConfiguration(tlsPolicy, environment)).to.throw(
      PrivateDatasetError,
      'private_dataset_tls_identity_invalid'
    )
    tlsPolicy.tls!.serverName = 'crab-export.internal'

    chmodSync(keyFile, 0o644)
    expect(() => assertPrivateDatasetConfiguration(tlsPolicy, environment)).to.throw(
      PrivateDatasetError,
      'private_dataset_tls_file_invalid'
    )
    chmodSync(keyFile, 0o600)

    const keyLink = path.join(directory, 'client-key-link.pem')
    symlinkSync(keyFile, keyLink)
    tlsPolicy.tls!.clientKeyFile = keyLink
    expect(() => assertPrivateDatasetConfiguration(tlsPolicy, environment)).to.throw(
      PrivateDatasetError,
      'private_dataset_tls_file_invalid'
    )
  })
})
