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

const twenty = (participant: Record<string, unknown>) =>
  Array.from({ length: 20 }, (_, index) => ({
    ...structuredClone(participant),
    subjectId: (index + 1).toString(16).padStart(64, '0')
  }))

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
  let receivedAlgorithmVersion: string
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
    receivedAlgorithmVersion = ''
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
      receivedAlgorithmVersion = String(
        request.headers['x-brainstem-algorithm-version'] ?? ''
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
          : { 'X-Brainstem-Source-Snapshot-SHA256': 'e'.repeat(64) }),
        ...(responseMode === 'no-sequence'
          ? {}
          : { 'X-Brainstem-Release-Sequence-SHA256': '9'.repeat(64) })
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

  it('rejects caller control of the algorithm version header before fetching', async () => {
    file.headers = {
      'X-Brainstem-Algorithm-Version': 'researcher-controlled'
    }
    await expectFailure('private_dataset_algorithm_version_header_is_reserved')
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
    expect(receivedAlgorithmVersion).to.equal('0.1.0')
    rmSync(destination)

    responseMode = 'no-sequence'
    await expectFailure('private_dataset_release_sequence_invalid')
    responseMode = 'valid'

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

  it('accepts only the exact seven-night sleep reliability contract', async () => {
    policy = {
      ...policy,
      maxBytes: 16 * 1024 * 1024,
      analysisId: 'brainstem.sleep-reliability-benchmark/v1',
      paperInsight: {
        algorithmVersion: '0.3.0',
        inputSchema: 'brainstem.sleep-nightly-features-cohort/v1',
        candidateManifestSha256:
          'b9bcc30891ffa7368f6169947b9aea9e2bb968a4a4db56287bd1ffde98d94073',
        approvedManifestSha256: 'd'.repeat(64),
        referenceSha256: null,
        evidenceTier: 'E0_candidate',
        useClass: 'methods_only',
        clinicalUse: 'prohibited'
      }
    }
    const night = (index: number) => ({
      schema: 'brainstem.sleep-nightly-features/v1',
      nightIndex: index,
      durationSeconds: 18_000,
      observedIntervalCount: 18_000,
      acceptedIntervalCount: 18_000,
      intervalSumMs: 18_000_000,
      durationCoverageRatio: 1,
      normalToNormalProvenance: 'unverified',
      officialMethodInputCompatible: false
    })
    const dataset: any = {
      schema: 'brainstem.sleep-nightly-features-cohort/v1',
      policy: 'brainstem.full-night-nightly-features/exact-distinct-7/v1',
      allowedUse: 'aggregate_sleep_reliability_only',
      sourceType: 'approved_real_cohort',
      sourceReleaseSha256: 'e'.repeat(64),
      sourceSnapshotSha256: 'f'.repeat(64),
      participants: twenty({
        subjectId: '1'.repeat(64),
        referenceProfile: {
          schema: 'brainstem.reference-profile/v1',
          referenceYear: 2026,
          ageBand: '30_44',
          gender: null,
          region: null
        },
        nights: Array.from({ length: 7 }, (_, index) => night(index + 1))
      })
    }
    body = Buffer.from(JSON.stringify(dataset))
    await downloadPrivateDataset(file, destination, JOB_ID, policy, environment)
    expect(receivedAnalysisId).to.equal('brainstem.sleep-reliability-benchmark/v1')
    expect(receivedAlgorithmVersion).to.equal('0.3.0')
    rmSync(destination)

    const drifted = structuredClone(dataset)
    Object.assign(drifted.participants[0].nights[0], {
      recordingDate: '2026-08-31'
    })
    body = Buffer.from(JSON.stringify(drifted))
    await expectFailure('private_dataset_contract_invalid')
  })

  it('accepts the exact expansion cohort contracts', async () => {
    const basePaper = {
      algorithmVersion: '0.1.0' as const,
      approvedManifestSha256: 'd'.repeat(64),
      referenceSha256: null as null,
      useClass: 'methods_only' as const,
      clinicalUse: 'prohibited' as const
    }
    policy = {
      ...policy,
      maxBytes: 16 * 1024 * 1024,
      analysisId: 'brainstem.overnight-heart-rate-change/v1',
      paperInsight: {
        ...basePaper,
        algorithmVersion: '0.2.0',
        inputSchema: 'brainstem.overnight-heart-rate-change-cohort/v2',
        candidateManifestSha256:
          '56e996b4cde15689b7524e7e9427b7fc67dd722d77493fd1daac67d421d90907',
        evidenceTier: 'E1_public_reproduced'
      }
    }
    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.overnight-heart-rate-change-cohort/v2',
        policy: 'brainstem.overnight-heart-rate-change-cohort/distinct-9-movement/v2',
        allowedUse: 'aggregate_overnight_change_only',
        sourceType: 'approved_real_cohort',
        movementSchema: 'brainstem.normalized-movement/v1',
        movementThresholdMilliG: 100,
        participants: twenty({
          subjectId: '1'.repeat(64),
          nights: Array.from({ length: 9 }, (_, index) => ({
            nightIndex: index + 1,
            durationSeconds: 18000,
            observedIntervalCount: 18000,
            acceptedIntervalCount: 18000,
            intervalSumMs: 18000000,
            durationCoverageRatio: 1,
            movementCoverageFraction: 1,
            alignedHeartRateSampleFraction: 1,
            movementEventCount: 10,
            movementEventRatePerHour: 2,
            quietWindowProportion: 0.9,
            quietMeanHeartRateBpm: 60,
            movementMeanHeartRateBpm: 72,
            normalToNormalProvenance: 'unverified',
            officialMethodInputCompatible: false
          }))
        })
      })
    )
    await downloadPrivateDataset(file, destination, JOB_ID, policy, environment)
    rmSync(destination)

    const invalidOvernight = JSON.parse(body.toString())
    invalidOvernight.participants[0].nights[0].rawMovementSamples = [[0, 0, 1000]]
    body = Buffer.from(JSON.stringify(invalidOvernight))
    await expectFailure('private_dataset_contract_invalid')

    const intervals = Array(600).fill(500)
    policy = {
      ...policy,
      analysisId: 'brainstem.resting-hrv-repeatability/v1',
      paperInsight: {
        ...basePaper,
        inputSchema: 'brainstem.resting-hrv-repeatability-cohort/v1',
        candidateManifestSha256:
          '09e22348e350bb9e1da7183929675f7d67e718eb183075a7735c5513468905dd',
        evidenceTier: 'E0_candidate'
      }
    }
    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.resting-hrv-repeatability-cohort/v1',
        policy: 'brainstem.resting-hrv-repeatability-cohort/distinct-7/v1',
        allowedUse: 'aggregate_resting_repeatability_only',
        sourceType: 'approved_real_cohort',
        participants: twenty({
          subjectId: '2'.repeat(64),
          recordings: Array.from({ length: 7 }, () => ({
            recordingType: 'rest',
            durationSeconds: 300,
            rrIntervalsMs: intervals
          }))
        })
      })
    )
    await downloadPrivateDataset(file, destination, JOB_ID, policy, environment)
    expect(receivedAnalysisId).to.equal('brainstem.resting-hrv-repeatability/v1')
    rmSync(destination)

    policy = {
      ...policy,
      analysisId: 'brainstem.standing-heart-rate-response/v1',
      paperInsight: {
        ...basePaper,
        inputSchema: 'brainstem.standing-heart-rate-response-cohort/v1',
        candidateManifestSha256:
          'ee503af519ed241f1f7ec965b58ad41b38c622c71a43e3f44c86743722ac4217',
        evidenceTier: 'E2_brainstem_compatible_exploratory'
      }
    }
    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.standing-heart-rate-response-cohort/v1',
        policy: 'brainstem.standing-heart-rate-response-cohort/latest-7/v1',
        allowedUse: 'aggregate_standing_response_only',
        sourceType: 'approved_real_cohort',
        participants: twenty({
          subjectId: '3'.repeat(64),
          recordings: [
            {
              recordingType: 'posture',
              durationSeconds: 300,
              rrIntervalsMs: Array(600).fill(500)
            }
          ]
        })
      })
    )
    await downloadPrivateDataset(file, destination, JOB_ID, policy, environment)
    expect(receivedAnalysisId).to.equal('brainstem.standing-heart-rate-response/v1')
    rmSync(destination)

    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.standing-heart-rate-response-cohort/v1',
        policy: 'brainstem.standing-heart-rate-response-cohort/latest-7/v1',
        allowedUse: 'aggregate_standing_response_only',
        sourceType: 'approved_real_cohort',
        participants: [
          {
            subjectId: '3'.repeat(64),
            recordings: [
              {
                recordingType: 'rest',
                durationSeconds: 300,
                rrIntervalsMs: Array(600).fill(500)
              }
            ]
          }
        ]
      })
    )
    await expectFailure('private_dataset_contract_invalid')

    policy = {
      ...policy,
      analysisId: 'brainstem.guided-breathing-response/v1',
      paperInsight: {
        ...basePaper,
        inputSchema: 'brainstem.guided-breathing-response-cohort/v1',
        candidateManifestSha256:
          'e64490c6539db744350ee761db4a1fedffd6f9f631f8814480a684c1fdc4931d',
        evidenceTier: 'E2_brainstem_compatible_exploratory'
      }
    }
    const protocol = { rateCPM: 6, ih: 5, ip: 0, eh: 5, ep: 0 }
    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.guided-breathing-response-cohort/v1',
        policy:
          'brainstem.guided-breathing-response-cohort/protocol-6-5-0-5-0/latest-7/v1',
        allowedUse: 'aggregate_guided_breathing_response_only',
        sourceType: 'approved_real_cohort',
        protocol,
        participants: twenty({
          subjectId: '4'.repeat(64),
          recordings: [
            {
              recordingIndex: 1,
              recordingType: 'exercise',
              durationSeconds: 300,
              protocol,
              rrIntervalsMs: Array(300).fill(1000)
            }
          ]
        })
      })
    )
    await downloadPrivateDataset(file, destination, JOB_ID, policy, environment)
    expect(receivedAnalysisId).to.equal('brainstem.guided-breathing-response/v1')
    rmSync(destination)

    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.guided-breathing-response-cohort/v1',
        policy:
          'brainstem.guided-breathing-response-cohort/protocol-6-5-0-5-0/latest-7/v1',
        allowedUse: 'aggregate_guided_breathing_response_only',
        sourceType: 'approved_real_cohort',
        protocol,
        participants: [
          {
            subjectId: '4'.repeat(64),
            recordings: [
              {
                recordingIndex: 1,
                recordingType: 'exercise',
                durationSeconds: 300,
                protocol: { ...protocol, rateCPM: 5 },
                rrIntervalsMs: Array(300).fill(1000)
              }
            ]
          }
        ]
      })
    )
    await expectFailure('private_dataset_contract_invalid')

    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.guided-breathing-response-cohort/v1',
        policy:
          'brainstem.guided-breathing-response-cohort/protocol-6-5-0-5-0/latest-7/v1',
        allowedUse: 'aggregate_guided_breathing_response_only',
        sourceType: 'approved_real_cohort',
        protocol,
        participants: [
          {
            subjectId: '4'.repeat(64),
            recordings: [1, 2].map(() => ({
              recordingIndex: 1,
              recordingType: 'exercise',
              durationSeconds: 300,
              protocol,
              rrIntervalsMs: Array(300).fill(1000)
            }))
          }
        ]
      })
    )
    await expectFailure('private_dataset_contract_invalid')
  })

  it('requires reviewed study bindings and exact v2 protocol provenance', async () => {
    const study = {
      proposalId: 'study_a',
      revisionId: 'revision_b',
      revisionSha256: 'c'.repeat(64),
      dataPermitId: `data_permit_${'d'.repeat(32)}`,
      resultBearerTokenEnv: 'STUDY_RESULT_TEST_TOKEN'
    }
    const postureProtocol = {
      protocolId: 'brainstem.active-stand',
      protocolVersion: 1,
      warmUpSeconds: 120,
      restSeconds: 120,
      standSeconds: 60
    }
    policy = {
      ...policy,
      maxBytes: 16 * 1024 * 1024,
      analysisId: 'brainstem.standing-heart-rate-response/v2',
      study,
      paperInsight: {
        algorithmVersion: '0.2.0',
        inputSchema: 'brainstem.standing-heart-rate-response-cohort/v2',
        candidateManifestSha256:
          '9dd1ff3e4ff551b128f44f61fdf33799f1e7514af5cd505eeae4b2db67a496fa',
        approvedManifestSha256:
          '7351da697fed84e68afbc440aef1d43f1de834363a862b8d912fa831f13e61b0',
        referenceSha256:
          '188183a7b0ac8c046d1139219f252ed37142505107ee94d69472bf43105eb3cb',
        evidenceTier: 'E2_brainstem_compatible_exploratory',
        useClass: 'methods_only',
        clinicalUse: 'prohibited'
      }
    }
    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.standing-heart-rate-response-cohort/v2',
        policy: 'brainstem.standing-heart-rate-response-cohort/latest-7/v2',
        allowedUse: 'aggregate_standing_response_only',
        sourceType: 'approved_real_cohort',
        participants: twenty({
          subjectId: '1'.repeat(64),
          recordings: [
            {
              recordingType: 'posture',
              durationSeconds: 300,
              protocol: postureProtocol,
              sourcePlatform: 'ios',
              rrIntervalsMs: Array(600).fill(500)
            }
          ]
        })
      })
    )
    await downloadPrivateDataset(file, destination, JOB_ID, policy, environment)
    expect(receivedStudyProposalId).to.equal('study_a')
    rmSync(destination)

    expect(() =>
      assertPrivateDatasetConfiguration({ ...policy, study: undefined }, environment)
    ).to.throw(PrivateDatasetError, 'private_dataset_policy_invalid')

    policy = {
      ...policy,
      analysisId: 'brainstem.guided-breathing-response/v2',
      paperInsight: {
        ...policy.paperInsight!,
        inputSchema: 'brainstem.guided-breathing-response-cohort/v2',
        candidateManifestSha256:
          '37448779b23897895c535e89ecc2c91fe25c588a0bcab533ed34a94a0ec2a039',
        approvedManifestSha256:
          '0756610a32d48784d8ed3b7367bf164865b27aa1fe1a05517052b2b3dd292cb8',
        referenceSha256:
          '79090c71b0e219a6bb6b940bdcb251e2cfa3e9630a30de7534694e9caef8b2ec'
      }
    }
    const breathingProtocol = { rateCPM: 6, ih: 5, ip: 0, eh: 5, ep: 0 }
    body = Buffer.from(
      JSON.stringify({
        schema: 'brainstem.guided-breathing-response-cohort/v2',
        policy:
          'brainstem.guided-breathing-response-cohort/protocol-6-5-0-5-0/latest-7/v2',
        allowedUse: 'aggregate_guided_breathing_response_only',
        sourceType: 'approved_real_cohort',
        protocol: breathingProtocol,
        participants: twenty({
          subjectId: '2'.repeat(64),
          recordings: [
            {
              recordingIndex: 1,
              recordingType: 'exercise',
              durationSeconds: 300,
              exerciseSubtype: 'guided_breathing',
              protocol: breathingProtocol,
              protocolVersion: 1,
              protocolSource: 'brainstem_app_prescribed',
              breathingAdherenceMeasured: false,
              sourcePlatform: 'android',
              rrIntervalsMs: Array(300).fill(1000)
            }
          ]
        })
      })
    )
    await downloadPrivateDataset(file, destination, JOB_ID, policy, environment)
    rmSync(destination)

    const drifted = JSON.parse(body.toString())
    drifted.participants[0].recordings[0].breathingAdherenceMeasured = true
    body = Buffer.from(JSON.stringify(drifted))
    await expectFailure('private_dataset_contract_invalid')
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
