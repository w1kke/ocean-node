/* eslint-disable security/detect-non-literal-fs-filename */
import axios from 'axios'
import { createHash, timingSafeEqual } from 'crypto'
import {
  createWriteStream,
  existsSync,
  lstatSync,
  readFileSync,
  renameSync,
  rmSync
} from 'fs'
import { Agent as HttpsAgent } from 'https'
import { Readable, Transform } from 'stream'
import { pipeline } from 'stream/promises'
import type { PrivateDatasetPolicy } from '../../@types/C2D/C2D.js'
import type { UrlFileObject } from '../../@types/fileObject.js'

const JOB_ID = /^[0-9a-f]{64}$/
const SHA256 = /^[0-9a-f]{64}$/
const JOB_HEADER = 'x-ocean-compute-job-id'
const RELEASE_HEADER = 'x-brainstem-cohort-release-id'
const ANALYSIS_HEADER = 'x-brainstem-analysis-id'
const STUDY_PROPOSAL_HEADER = 'x-brainstem-study-proposal-id'
const STUDY_REVISION_HEADER = 'x-brainstem-study-revision-id'
const STUDY_REVISION_SHA256_HEADER = 'x-brainstem-study-revision-sha256'
const STUDY_DATA_PERMIT_HEADER = 'x-brainstem-study-data-permit-id'
const ALGORITHM_VERSION_HEADER = 'x-brainstem-algorithm-version'
const METHODS_CANDIDATE_SHA256 =
  '15dbf8544c87d81c06f5e512b00e9fe39dd6431dd1a4079a97da68a3f92721c1'
const SAMPLE_ENTROPY_CANDIDATE_SHA256 =
  '65002ab13f02f812c611085c0295b81dc90ec7ffacc79f9ff4927e81e9070bdd'
const MINIMUM_DISCLOSURE_PARTICIPANTS = 20
const MAX_PRIVATE_DATASET_BYTES = 16 * 1024 * 1024
const SLEEP_RELIABILITY_CANDIDATE_SHA256 =
  'b9bcc30891ffa7368f6169947b9aea9e2bb968a4a4db56287bd1ffde98d94073'
const OVERNIGHT_CHANGE_CANDIDATE_SHA256 =
  '56e996b4cde15689b7524e7e9427b7fc67dd722d77493fd1daac67d421d90907'
const MOVEMENT_SCHEMA = 'brainstem.normalized-movement/v1'
const MOVEMENT_THRESHOLD_MILLIG = 100
const REST_REPEATABILITY_CANDIDATE_SHA256 =
  '09e22348e350bb9e1da7183929675f7d67e718eb183075a7735c5513468905dd'
const STANDING_RESPONSE_CANDIDATE_SHA256 =
  'ee503af519ed241f1f7ec965b58ad41b38c622c71a43e3f44c86743722ac4217'
const GUIDED_BREATHING_CANDIDATE_SHA256 =
  'e64490c6539db744350ee761db4a1fedffd6f9f631f8814480a684c1fdc4931d'
const STANDING_RESPONSE_V2_CANDIDATE_SHA256 =
  '9dd1ff3e4ff551b128f44f61fdf33799f1e7514af5cd505eeae4b2db67a496fa'
const STANDING_RESPONSE_V2_MANIFEST_SHA256 =
  '7351da697fed84e68afbc440aef1d43f1de834363a862b8d912fa831f13e61b0'
const STANDING_RESPONSE_V2_REFERENCE_SHA256 =
  '188183a7b0ac8c046d1139219f252ed37142505107ee94d69472bf43105eb3cb'
const GUIDED_BREATHING_V2_CANDIDATE_SHA256 =
  '37448779b23897895c535e89ecc2c91fe25c588a0bcab533ed34a94a0ec2a039'
const GUIDED_BREATHING_V2_MANIFEST_SHA256 =
  '0756610a32d48784d8ed3b7367bf164865b27aa1fe1a05517052b2b3dd292cb8'
const GUIDED_BREATHING_V2_REFERENCE_SHA256 =
  '79090c71b0e219a6bb6b940bdcb251e2cfa3e9630a30de7534694e9caef8b2ec'
type PrivateTransportPolicy = Omit<PrivateDatasetPolicy, 'analysisId' | 'paperInsight'> &
  Partial<Pick<PrivateDatasetPolicy, 'analysisId' | 'paperInsight'>>

export class PrivateDatasetError extends Error {
  constructor(code: string) {
    super(code)
    this.name = 'PrivateDatasetError'
  }
}

export function isLocalProofHostname(hostname: string): boolean {
  const parts = hostname.split('.')
  const loopbackIpv4 =
    parts.length === 4 &&
    parts[0] === '127' &&
    parts.every(
      (part) =>
        part.length > 0 &&
        [...part].every((character) => character >= '0' && character <= '9') &&
        Number(part) <= 255
    )
  const singleLabel =
    !hostname.includes('.') &&
    hostname.length > 0 &&
    hostname.length <= 63 &&
    !hostname.startsWith('-') &&
    !hostname.endsWith('-') &&
    [...hostname].every(
      (character) =>
        (character >= 'a' && character <= 'z') ||
        (character >= '0' && character <= '9') ||
        character === '-'
    )
  return hostname === 'localhost' || loopbackIpv4 || singleLabel
}

function isGuidedBreathingProtocol(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const protocol = value as Record<string, unknown>
  return (
    Object.keys(protocol).sort().join(',') === 'eh,ep,ih,ip,rateCPM' &&
    protocol.rateCPM === 6 &&
    protocol.ih === 5 &&
    protocol.ip === 0 &&
    protocol.eh === 5 &&
    protocol.ep === 0
  )
}

function isPostureProtocol(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const protocol = value as Record<string, unknown>
  return (
    Object.keys(protocol).sort().join(',') ===
      'protocolId,protocolVersion,restSeconds,standSeconds,warmUpSeconds' &&
    protocol.protocolId === 'brainstem.active-stand' &&
    protocol.protocolVersion === 1 &&
    protocol.warmUpSeconds === 120 &&
    protocol.restSeconds === 120 &&
    protocol.standSeconds === 60
  )
}

function hasStudyBinding(policy: PrivateTransportPolicy): boolean {
  return Boolean(
    policy.study &&
    /^study_[0-9a-f]{1,64}$/.test(policy.study.proposalId) &&
    /^revision_[0-9a-f]{1,64}$/.test(policy.study.revisionId) &&
    SHA256.test(policy.study.revisionSha256) &&
    /^data_permit_[0-9a-f]{32}$/.test(policy.study.dataPermitId) &&
    /^[A-Z][A-Z0-9_]{0,63}$/.test(policy.study.resultBearerTokenEnv) &&
    policy.study.resultBearerTokenEnv !== policy.bearerTokenEnv
  )
}

function isSleepNight(value: unknown, index: number, withSchema: boolean): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const night = value as Record<string, unknown>
  return (
    (!withSchema || night.schema === 'brainstem.sleep-nightly-features/v1') &&
    night.nightIndex === index + 1 &&
    Number.isInteger(night.durationSeconds) &&
    (night.durationSeconds as number) >= 18_000 &&
    (night.durationSeconds as number) <= 43_200 &&
    Number.isInteger(night.observedIntervalCount) &&
    Number.isInteger(night.acceptedIntervalCount) &&
    (night.acceptedIntervalCount as number) >= 9_000 &&
    (night.acceptedIntervalCount as number) <= (night.observedIntervalCount as number) &&
    (night.acceptedIntervalCount as number) / (night.observedIntervalCount as number) >=
      0.95 &&
    typeof night.intervalSumMs === 'number' &&
    Number.isFinite(night.intervalSumMs) &&
    (night.intervalSumMs as number) >= 250 * (night.acceptedIntervalCount as number) &&
    (night.intervalSumMs as number) <= 2_000 * (night.acceptedIntervalCount as number) &&
    typeof night.durationCoverageRatio === 'number' &&
    Number.isFinite(night.durationCoverageRatio) &&
    night.durationCoverageRatio >= 0.9 &&
    night.durationCoverageRatio <= 1.1 &&
    Math.abs(
      night.durationCoverageRatio -
        (night.intervalSumMs as number) / 1000 / (night.durationSeconds as number)
    ) <= 0.000001 &&
    night.normalToNormalProvenance === 'unverified' &&
    night.officialMethodInputCompatible === false
  )
}

function isReferenceProfile(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const profile = value as Record<string, unknown>
  return (
    Object.keys(profile).sort().join(',') ===
      'ageBand,gender,referenceYear,region,schema' &&
    profile.schema === 'brainstem.reference-profile/v1' &&
    profile.referenceYear === 2026 &&
    [null, 'under_30', '30_44', '45_59', '60_plus'].includes(
      profile.ageBand as string | null
    ) &&
    [null, 'female', 'male'].includes(profile.gender as string | null) &&
    [
      null,
      'North America',
      'Europe',
      'South East Asia',
      'East Asia',
      'Middle East',
      'South America',
      'Central Asia',
      'Other'
    ].includes(profile.region as string | null)
  )
}

export function assertPrivateDatasetJob(
  policy: PrivateDatasetPolicy,
  image: string,
  assetCount: number,
  hasRemoteOutput: boolean = false
): void {
  if (image !== policy.approvedAlgorithmImage) {
    throw new PrivateDatasetError('private_dataset_algorithm_not_approved')
  }
  if (assetCount !== 1) {
    throw new PrivateDatasetError('private_dataset_requires_one_asset')
  }
  if (hasRemoteOutput) {
    throw new PrivateDatasetError('private_dataset_remote_output_not_allowed')
  }
}

export function assertPrivateDatasetConfiguration(
  policy: PrivateTransportPolicy,
  environment: NodeJS.ProcessEnv = process.env
): void {
  if (
    !Number.isSafeInteger(policy.maxBytes) ||
    policy.maxBytes < 1 ||
    policy.maxBytes > MAX_PRIVATE_DATASET_BYTES
  ) {
    throw new PrivateDatasetError('private_dataset_size_limit_invalid')
  }
  if (
    policy.analysisId === 'brainstem.resting-rr-cohort-summary/v1' &&
    (policy.paperInsight !== undefined || policy.study !== undefined)
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.resting-hrv-methods/v1' &&
    (policy.study !== undefined ||
      policy.paperInsight?.algorithmVersion !== '0.1.0' ||
      policy.paperInsight.inputSchema !== 'brainstem.resting-hrv-methods-cohort/v1' ||
      policy.paperInsight.candidateManifestSha256 !== METHODS_CANDIDATE_SHA256 ||
      !SHA256.test(policy.paperInsight.approvedManifestSha256) ||
      !SHA256.test(policy.paperInsight.referenceSha256) ||
      policy.paperInsight.evidenceTier !== 'E2_brainstem_compatible_exploratory' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited')
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.resting-rr-sample-entropy/v1' &&
    (policy.study !== undefined ||
      policy.paperInsight?.algorithmVersion !== '0.1.0' ||
      policy.paperInsight.inputSchema !== 'brainstem.resting-sample-entropy-cohort/v1' ||
      policy.paperInsight.candidateManifestSha256 !== SAMPLE_ENTROPY_CANDIDATE_SHA256 ||
      !SHA256.test(policy.paperInsight.approvedManifestSha256) ||
      !SHA256.test(policy.paperInsight.referenceSha256) ||
      policy.paperInsight.evidenceTier !== 'E2_brainstem_compatible_exploratory' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited')
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.full-night-rr-signal-compatibility/v1' &&
    (!hasStudyBinding(policy) ||
      policy.paperInsight !== undefined ||
      policy.participantValue !== undefined)
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.sleep-reliability-benchmark/v1' &&
    (policy.paperInsight?.algorithmVersion !== '0.3.0' ||
      policy.paperInsight.inputSchema !== 'brainstem.sleep-nightly-features-cohort/v1' ||
      policy.paperInsight.candidateManifestSha256 !==
        SLEEP_RELIABILITY_CANDIDATE_SHA256 ||
      !SHA256.test(policy.paperInsight.approvedManifestSha256) ||
      policy.paperInsight.referenceSha256 !== null ||
      policy.paperInsight.evidenceTier !== 'E0_candidate' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited')
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.overnight-heart-rate-change/v1' &&
    (policy.paperInsight?.algorithmVersion !== '0.2.0' ||
      policy.paperInsight.inputSchema !==
        'brainstem.overnight-heart-rate-change-cohort/v2' ||
      policy.paperInsight.candidateManifestSha256 !== OVERNIGHT_CHANGE_CANDIDATE_SHA256 ||
      !SHA256.test(policy.paperInsight.approvedManifestSha256) ||
      policy.paperInsight.referenceSha256 !== null ||
      policy.paperInsight.evidenceTier !== 'E1_public_reproduced' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited')
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.resting-hrv-repeatability/v1' &&
    (policy.paperInsight?.algorithmVersion !== '0.1.0' ||
      policy.paperInsight.inputSchema !==
        'brainstem.resting-hrv-repeatability-cohort/v1' ||
      policy.paperInsight.candidateManifestSha256 !==
        REST_REPEATABILITY_CANDIDATE_SHA256 ||
      !SHA256.test(policy.paperInsight.approvedManifestSha256) ||
      policy.paperInsight.referenceSha256 !== null ||
      policy.paperInsight.evidenceTier !== 'E0_candidate' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited')
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.standing-heart-rate-response/v1' &&
    (policy.paperInsight?.algorithmVersion !== '0.1.0' ||
      policy.paperInsight.inputSchema !==
        'brainstem.standing-heart-rate-response-cohort/v1' ||
      policy.paperInsight.candidateManifestSha256 !==
        STANDING_RESPONSE_CANDIDATE_SHA256 ||
      !SHA256.test(policy.paperInsight.approvedManifestSha256) ||
      policy.paperInsight.referenceSha256 !== null ||
      policy.paperInsight.evidenceTier !== 'E2_brainstem_compatible_exploratory' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited')
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.guided-breathing-response/v1' &&
    (policy.paperInsight?.algorithmVersion !== '0.1.0' ||
      policy.paperInsight.inputSchema !==
        'brainstem.guided-breathing-response-cohort/v1' ||
      policy.paperInsight.candidateManifestSha256 !== GUIDED_BREATHING_CANDIDATE_SHA256 ||
      !SHA256.test(policy.paperInsight.approvedManifestSha256) ||
      policy.paperInsight.referenceSha256 !== null ||
      policy.paperInsight.evidenceTier !== 'E2_brainstem_compatible_exploratory' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited')
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.standing-heart-rate-response/v2' &&
    (!hasStudyBinding(policy) ||
      policy.paperInsight?.algorithmVersion !== '0.2.0' ||
      policy.paperInsight.inputSchema !==
        'brainstem.standing-heart-rate-response-cohort/v2' ||
      policy.paperInsight.candidateManifestSha256 !==
        STANDING_RESPONSE_V2_CANDIDATE_SHA256 ||
      policy.paperInsight.approvedManifestSha256 !==
        STANDING_RESPONSE_V2_MANIFEST_SHA256 ||
      policy.paperInsight.referenceSha256 !== STANDING_RESPONSE_V2_REFERENCE_SHA256 ||
      policy.paperInsight.evidenceTier !== 'E2_brainstem_compatible_exploratory' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited' ||
      policy.participantValue !== undefined)
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  if (
    policy.analysisId === 'brainstem.guided-breathing-response/v2' &&
    (!hasStudyBinding(policy) ||
      policy.paperInsight?.algorithmVersion !== '0.2.0' ||
      policy.paperInsight.inputSchema !==
        'brainstem.guided-breathing-response-cohort/v2' ||
      policy.paperInsight.candidateManifestSha256 !==
        GUIDED_BREATHING_V2_CANDIDATE_SHA256 ||
      policy.paperInsight.approvedManifestSha256 !==
        GUIDED_BREATHING_V2_MANIFEST_SHA256 ||
      policy.paperInsight.referenceSha256 !== GUIDED_BREATHING_V2_REFERENCE_SHA256 ||
      policy.paperInsight.evidenceTier !== 'E2_brainstem_compatible_exploratory' ||
      policy.paperInsight.useClass !== 'methods_only' ||
      policy.paperInsight.clinicalUse !== 'prohibited' ||
      policy.participantValue !== undefined)
  ) {
    throw new PrivateDatasetError('private_dataset_policy_invalid')
  }
  const bearerToken = environment[policy.bearerTokenEnv]
  if (
    typeof bearerToken !== 'string' ||
    bearerToken.length < 32 ||
    bearerToken.includes('\n') ||
    bearerToken.includes('\r')
  ) {
    throw new PrivateDatasetError('private_dataset_credential_invalid')
  }
  if (policy.study) {
    const resultToken = environment[policy.study.resultBearerTokenEnv]
    if (
      typeof resultToken !== 'string' ||
      resultToken.length < 32 ||
      resultToken.includes('\n') ||
      resultToken.includes('\r') ||
      resultToken === bearerToken
    ) {
      throw new PrivateDatasetError('private_dataset_credential_invalid')
    }
  }
  const url = new URL(policy.url)
  if (
    url.protocol !== 'https:' &&
    !(
      policy.allowInsecureLocalProof === true &&
      url.protocol === 'http:' &&
      isLocalProofHostname(url.hostname)
    )
  ) {
    throw new PrivateDatasetError('private_dataset_transport_invalid')
  }
  if (!isLocalProofHostname(url.hostname) && !policy.tls) {
    throw new PrivateDatasetError('private_dataset_transport_invalid')
  }
  if (!policy.tls) return

  if (
    url.protocol !== 'https:' ||
    url.hostname.toLowerCase() !== policy.tls.serverName.toLowerCase()
  ) {
    throw new PrivateDatasetError('private_dataset_tls_identity_invalid')
  }
  for (const [file, privateFile] of [
    [policy.tls.caFile, false],
    [policy.tls.clientCertificateFile, false],
    [policy.tls.clientKeyFile, true]
  ] as Array<[string, boolean]>) {
    try {
      const fileStat = lstatSync(file)
      if (
        fileStat.isSymbolicLink() ||
        !fileStat.isFile() ||
        fileStat.size < 1 ||
        fileStat.size > 64 * 1024 ||
        (privateFile ? (fileStat.mode & 0o077) !== 0 : (fileStat.mode & 0o022) !== 0)
      ) {
        throw new Error('unsafe TLS file')
      }
      readFileSync(file)
    } catch (_error) {
      throw new PrivateDatasetError('private_dataset_tls_file_invalid')
    }
  }
}

export function privateDatasetHttpsAgent(
  policy: PrivateTransportPolicy
): HttpsAgent | undefined {
  if (!policy.tls) return undefined
  return new HttpsAgent({
    ca: readFileSync(policy.tls.caFile),
    cert: readFileSync(policy.tls.clientCertificateFile),
    key: readFileSync(policy.tls.clientKeyFile),
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
    keepAlive: false,
    maxSockets: 1
  })
}

function requestHeaders(
  file: UrlFileObject,
  jobId: string,
  policy: PrivateDatasetPolicy,
  environment: NodeJS.ProcessEnv
): Record<string, string> {
  const suppliedHeaders = Object.entries(file.headers ?? {})
  for (const [key] of suppliedHeaders) {
    if (key.toLowerCase() === JOB_HEADER) {
      throw new PrivateDatasetError('private_dataset_job_header_is_reserved')
    }
    if (key.toLowerCase() === RELEASE_HEADER) {
      throw new PrivateDatasetError('private_dataset_release_header_is_reserved')
    }
    if (key.toLowerCase() === ANALYSIS_HEADER) {
      throw new PrivateDatasetError('private_dataset_analysis_header_is_reserved')
    }
    if (
      [
        STUDY_PROPOSAL_HEADER,
        STUDY_REVISION_HEADER,
        STUDY_REVISION_SHA256_HEADER,
        STUDY_DATA_PERMIT_HEADER
      ].includes(key.toLowerCase())
    ) {
      throw new PrivateDatasetError('private_dataset_study_header_is_reserved')
    }
    if (key.toLowerCase() === ALGORITHM_VERSION_HEADER) {
      throw new PrivateDatasetError(
        'private_dataset_algorithm_version_header_is_reserved'
      )
    }
  }
  if (suppliedHeaders.length > 0) {
    throw new PrivateDatasetError('private_dataset_headers_not_allowed')
  }
  assertPrivateDatasetConfiguration(policy, environment)
  return {
    Accept: 'application/json',
    'Accept-Encoding': 'identity',
    Authorization: `Bearer ${environment[policy.bearerTokenEnv]}`,
    'X-Ocean-Compute-Job-Id': jobId,
    'X-Brainstem-Cohort-Release-Id': policy.releaseId,
    'X-Brainstem-Analysis-Id': policy.analysisId,
    ...(policy.study
      ? {
          'X-Brainstem-Study-Proposal-Id': policy.study.proposalId,
          'X-Brainstem-Study-Revision-Id': policy.study.revisionId,
          'X-Brainstem-Study-Revision-SHA256': policy.study.revisionSha256,
          'X-Brainstem-Study-Data-Permit-Id': policy.study.dataPermitId
        }
      : {}),
    ...(policy.paperInsight
      ? { 'X-Brainstem-Algorithm-Version': policy.paperInsight.algorithmVersion }
      : {})
  }
}

function requiredHeader(value: unknown, pattern: RegExp, code: string): string {
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw new PrivateDatasetError(code)
  }
  return value
}

function validateReviewedCohortInput(
  destination: string,
  policy: PrivateDatasetPolicy
): void {
  if (!policy.paperInsight && !policy.study) return
  try {
    const dataset = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(destination))
    )
    if (
      policy.study &&
      policy.analysisId === 'brainstem.full-night-rr-signal-compatibility/v1'
    ) {
      if (
        !dataset ||
        Array.isArray(dataset) ||
        Object.keys(dataset).sort().join(',') !== 'participants,policy,schema' ||
        dataset.schema !== 'brainstem.full-night-rr-cohort/v1' ||
        dataset.policy !== 'brainstem.full-night-rr-signal-compatibility/v1' ||
        !Array.isArray(dataset.participants) ||
        dataset.participants.length < MINIMUM_DISCLOSURE_PARTICIPANTS ||
        dataset.participants.length > 100
      ) {
        throw new Error('invalid dataset')
      }
      const subjects = new Set<string>()
      for (const participant of dataset.participants) {
        const recording = participant?.recordings?.[0]
        const quality = recording?.quality
        if (
          !participant ||
          Array.isArray(participant) ||
          Object.keys(participant).sort().join(',') !== 'recordings,subjectId' ||
          typeof participant.subjectId !== 'string' ||
          !SHA256.test(participant.subjectId) ||
          subjects.has(participant.subjectId) ||
          !Array.isArray(participant.recordings) ||
          participant.recordings.length !== 1 ||
          !recording ||
          Array.isArray(recording) ||
          Object.keys(recording).sort().join(',') !==
            'allowedUse,durationSeconds,intervalSemantics,quality,recordingType,rrIntervalsMs' ||
          recording.recordingType !== 'sleep' ||
          recording.intervalSemantics !== 'detector_rr_unclassified' ||
          recording.allowedUse !== 'aggregate_method_compatibility_only' ||
          !Number.isInteger(recording.durationSeconds) ||
          recording.durationSeconds < 18000 ||
          recording.durationSeconds > 43200 ||
          !Array.isArray(recording.rrIntervalsMs) ||
          recording.rrIntervalsMs.length < 9000 ||
          recording.rrIntervalsMs.length > 172800 ||
          recording.rrIntervalsMs.some(
            (value: unknown) =>
              typeof value !== 'number' ||
              !Number.isFinite(value) ||
              value < 250 ||
              value > 2000
          ) ||
          !quality ||
          Array.isArray(quality) ||
          Object.keys(quality).sort().join(',') !==
            'acceptedFraction,acceptedIntervalCount,durationCoverageRatio,normalToNormalProvenance,observedIntervalCount,officialMethodInputCompatible' ||
          quality.normalToNormalProvenance !== 'unverified' ||
          quality.officialMethodInputCompatible !== false ||
          !Number.isInteger(quality.observedIntervalCount) ||
          quality.observedIntervalCount < recording.rrIntervalsMs.length ||
          quality.acceptedIntervalCount !== recording.rrIntervalsMs.length ||
          typeof quality.acceptedFraction !== 'number' ||
          !Number.isFinite(quality.acceptedFraction) ||
          quality.acceptedFraction < 0.95 ||
          Math.abs(
            quality.acceptedFraction -
              quality.acceptedIntervalCount / quality.observedIntervalCount
          ) > 0.000001 ||
          typeof quality.durationCoverageRatio !== 'number' ||
          !Number.isFinite(quality.durationCoverageRatio) ||
          quality.durationCoverageRatio < 0.9 ||
          quality.durationCoverageRatio > 1.1
        ) {
          throw new Error('invalid participant')
        }
        const intervalSeconds =
          recording.rrIntervalsMs.reduce(
            (total: number, value: number) => total + value,
            0
          ) / 1000
        if (
          quality.durationCoverageRatio <
            intervalSeconds / (recording.durationSeconds + 1) - 0.0000005 ||
          quality.durationCoverageRatio >
            intervalSeconds / recording.durationSeconds + 0.0000005
        ) {
          throw new Error('invalid participant')
        }
        subjects.add(participant.subjectId)
      }
      return
    }
    const overnight =
      policy.paperInsight.inputSchema ===
      'brainstem.overnight-heart-rate-change-cohort/v2'
    const sleepReliability =
      policy.paperInsight.inputSchema === 'brainstem.sleep-nightly-features-cohort/v1'
    const repeatability =
      policy.paperInsight.inputSchema === 'brainstem.resting-hrv-repeatability-cohort/v1'
    const standingV2 =
      policy.paperInsight.inputSchema ===
      'brainstem.standing-heart-rate-response-cohort/v2'
    const standing =
      policy.paperInsight.inputSchema ===
        'brainstem.standing-heart-rate-response-cohort/v1' || standingV2
    const guidedBreathingV2 =
      policy.paperInsight.inputSchema === 'brainstem.guided-breathing-response-cohort/v2'
    const guidedBreathing =
      policy.paperInsight.inputSchema ===
        'brainstem.guided-breathing-response-cohort/v1' || guidedBreathingV2
    if (
      !dataset ||
      Array.isArray(dataset) ||
      Object.keys(dataset).sort().join(',') !==
        (guidedBreathing
          ? 'allowedUse,participants,policy,protocol,schema,sourceType'
          : overnight
            ? 'allowedUse,movementSchema,movementThresholdMilliG,participants,policy,schema,sourceType'
            : sleepReliability
              ? 'allowedUse,participants,policy,schema,sourceReleaseSha256,sourceSnapshotSha256,sourceType'
              : repeatability || standing
                ? 'allowedUse,participants,policy,schema,sourceType'
                : 'participants,schema') ||
      dataset.schema !== policy.paperInsight.inputSchema ||
      ((overnight || sleepReliability || repeatability || standing || guidedBreathing) &&
        dataset.sourceType !== 'approved_real_cohort') ||
      (sleepReliability &&
        (dataset.policy !== 'brainstem.full-night-nightly-features/exact-distinct-7/v1' ||
          dataset.allowedUse !== 'aggregate_sleep_reliability_only' ||
          typeof dataset.sourceReleaseSha256 !== 'string' ||
          !SHA256.test(dataset.sourceReleaseSha256) ||
          typeof dataset.sourceSnapshotSha256 !== 'string' ||
          !SHA256.test(dataset.sourceSnapshotSha256))) ||
      (overnight &&
        (dataset.policy !==
          'brainstem.overnight-heart-rate-change-cohort/distinct-9-movement/v2' ||
          dataset.allowedUse !== 'aggregate_overnight_change_only' ||
          dataset.movementSchema !== MOVEMENT_SCHEMA ||
          dataset.movementThresholdMilliG !== MOVEMENT_THRESHOLD_MILLIG)) ||
      (repeatability &&
        (dataset.policy !== 'brainstem.resting-hrv-repeatability-cohort/distinct-7/v1' ||
          dataset.allowedUse !== 'aggregate_resting_repeatability_only')) ||
      (standing &&
        (dataset.policy !==
          (standingV2
            ? 'brainstem.standing-heart-rate-response-cohort/latest-7/v2'
            : 'brainstem.standing-heart-rate-response-cohort/latest-7/v1') ||
          dataset.allowedUse !== 'aggregate_standing_response_only')) ||
      (guidedBreathing &&
        (dataset.policy !==
          (guidedBreathingV2
            ? 'brainstem.guided-breathing-response-cohort/protocol-6-5-0-5-0/latest-7/v2'
            : 'brainstem.guided-breathing-response-cohort/protocol-6-5-0-5-0/latest-7/v1') ||
          dataset.allowedUse !== 'aggregate_guided_breathing_response_only' ||
          !isGuidedBreathingProtocol(dataset.protocol))) ||
      !Array.isArray(dataset.participants) ||
      dataset.participants.length < MINIMUM_DISCLOSURE_PARTICIPANTS ||
      dataset.participants.length > (sleepReliability ? 100 : 1000)
    ) {
      throw new Error('invalid dataset')
    }
    const subjects = new Set<string>()
    const sampleEntropy =
      policy.paperInsight.inputSchema === 'brainstem.resting-sample-entropy-cohort/v1'
    for (const participant of dataset.participants) {
      const values =
        overnight || sleepReliability ? participant?.nights : participant?.recordings
      if (
        !participant ||
        Array.isArray(participant) ||
        Object.keys(participant).sort().join(',') !==
          (sleepReliability
            ? 'nights,referenceProfile,subjectId'
            : overnight
              ? 'nights,subjectId'
              : 'recordings,subjectId') ||
        typeof participant.subjectId !== 'string' ||
        !SHA256.test(participant.subjectId) ||
        subjects.has(participant.subjectId) ||
        !Array.isArray(values) ||
        values.length < 1 ||
        values.length >
          (sleepReliability
            ? 7
            : overnight
              ? 9
              : repeatability || standing || guidedBreathing
                ? 7
                : sampleEntropy
                  ? 1
                  : 16) ||
        ((overnight || sleepReliability || repeatability) &&
          values.length !== (overnight ? 9 : 7)) ||
        (sleepReliability && !isReferenceProfile(participant.referenceProfile))
      ) {
        throw new Error('invalid participant')
      }
      subjects.add(participant.subjectId)
      if (sleepReliability) {
        for (let index = 0; index < values.length; index += 1) {
          const night = values[index]
          if (
            !night ||
            Array.isArray(night) ||
            Object.keys(night).sort().join(',') !==
              'acceptedIntervalCount,durationCoverageRatio,durationSeconds,intervalSumMs,nightIndex,normalToNormalProvenance,observedIntervalCount,officialMethodInputCompatible,schema' ||
            !isSleepNight(night, index, true)
          ) {
            throw new Error('invalid night')
          }
        }
        continue
      }
      if (overnight) {
        for (let index = 0; index < values.length; index += 1) {
          const night = values[index]
          if (
            !night ||
            Array.isArray(night) ||
            Object.keys(night).sort().join(',') !==
              'acceptedIntervalCount,alignedHeartRateSampleFraction,durationCoverageRatio,durationSeconds,intervalSumMs,movementCoverageFraction,movementEventCount,movementEventRatePerHour,movementMeanHeartRateBpm,nightIndex,normalToNormalProvenance,observedIntervalCount,officialMethodInputCompatible,quietMeanHeartRateBpm,quietWindowProportion' ||
            !isSleepNight(night, index, false) ||
            typeof night.movementCoverageFraction !== 'number' ||
            !Number.isFinite(night.movementCoverageFraction) ||
            night.movementCoverageFraction < 0.8 ||
            night.movementCoverageFraction > 1 ||
            typeof night.alignedHeartRateSampleFraction !== 'number' ||
            !Number.isFinite(night.alignedHeartRateSampleFraction) ||
            night.alignedHeartRateSampleFraction < 0.8 ||
            night.alignedHeartRateSampleFraction > 1 ||
            !Number.isInteger(night.movementEventCount) ||
            night.movementEventCount < 0 ||
            night.movementEventCount > night.durationSeconds ||
            typeof night.movementEventRatePerHour !== 'number' ||
            !Number.isFinite(night.movementEventRatePerHour) ||
            Math.abs(
              night.movementEventRatePerHour -
                night.movementEventCount / (night.durationSeconds / 3600)
            ) > 0.000001 ||
            typeof night.quietWindowProportion !== 'number' ||
            !Number.isFinite(night.quietWindowProportion) ||
            night.quietWindowProportion < 0 ||
            night.quietWindowProportion > 1 ||
            ![night.quietMeanHeartRateBpm, night.movementMeanHeartRateBpm].every(
              (value) =>
                value === null ||
                (typeof value === 'number' &&
                  Number.isFinite(value) &&
                  value >= 20 &&
                  value <= 250)
            ) ||
            (night.quietWindowProportion === 0) !==
              (night.quietMeanHeartRateBpm === null) ||
            (night.movementEventCount === 0) !==
              (night.movementMeanHeartRateBpm === null) ||
            night.normalToNormalProvenance !== 'unverified' ||
            night.officialMethodInputCompatible !== false
          ) {
            throw new Error('invalid night')
          }
        }
        continue
      }
      if (standing) {
        for (const recording of values) {
          const representedSeconds = Array.isArray(recording?.rrIntervalsMs)
            ? recording.rrIntervalsMs.reduce(
                (total: number, value: number) => total + value,
                0
              ) / 1000
            : Number.NaN
          if (
            !recording ||
            Array.isArray(recording) ||
            Object.keys(recording).sort().join(',') !==
              (standingV2
                ? 'durationSeconds,protocol,recordingType,rrIntervalsMs,sourcePlatform'
                : 'durationSeconds,recordingType,rrIntervalsMs') ||
            recording.recordingType !== 'posture' ||
            (standingV2 &&
              (!isPostureProtocol(recording.protocol) ||
                !['android', 'ios'].includes(recording.sourcePlatform))) ||
            !Number.isInteger(recording.durationSeconds) ||
            recording.durationSeconds < 295 ||
            recording.durationSeconds > 305 ||
            !Array.isArray(recording.rrIntervalsMs) ||
            recording.rrIntervalsMs.length < 148 ||
            recording.rrIntervalsMs.length > 1100 ||
            recording.rrIntervalsMs.some(
              (value: unknown) =>
                typeof value !== 'number' ||
                !Number.isFinite(value) ||
                value < 300 ||
                value > 2000
            ) ||
            representedSeconds < 295 ||
            representedSeconds > 305 ||
            Math.abs(representedSeconds - recording.durationSeconds) > 5
          ) {
            throw new Error('invalid recording')
          }
        }
        continue
      }
      if (guidedBreathing) {
        const indices = new Set<number>()
        for (const recording of values) {
          const coverage = Array.isArray(recording?.rrIntervalsMs)
            ? recording.rrIntervalsMs.reduce(
                (total: number, value: number) => total + value,
                0
              ) /
              1000 /
              recording.durationSeconds
            : Number.NaN
          if (
            !recording ||
            Array.isArray(recording) ||
            Object.keys(recording).sort().join(',') !==
              (guidedBreathingV2
                ? 'breathingAdherenceMeasured,durationSeconds,exerciseSubtype,protocol,protocolSource,protocolVersion,recordingIndex,recordingType,rrIntervalsMs,sourcePlatform'
                : 'durationSeconds,protocol,recordingIndex,recordingType,rrIntervalsMs') ||
            !Number.isInteger(recording.recordingIndex) ||
            recording.recordingIndex < 1 ||
            recording.recordingIndex > 7 ||
            indices.has(recording.recordingIndex) ||
            recording.recordingType !== 'exercise' ||
            (guidedBreathingV2 &&
              (recording.exerciseSubtype !== 'guided_breathing' ||
                recording.protocolVersion !== 1 ||
                recording.protocolSource !== 'brainstem_app_prescribed' ||
                recording.breathingAdherenceMeasured !== false ||
                !['android', 'ios'].includes(recording.sourcePlatform))) ||
            !Number.isInteger(recording.durationSeconds) ||
            recording.durationSeconds < 120 ||
            recording.durationSeconds > 1800 ||
            !isGuidedBreathingProtocol(recording.protocol) ||
            !Array.isArray(recording.rrIntervalsMs) ||
            recording.rrIntervalsMs.length < 1 ||
            recording.rrIntervalsMs.length > 6000 ||
            recording.rrIntervalsMs.some(
              (value: unknown) =>
                typeof value !== 'number' ||
                !Number.isFinite(value) ||
                value < 300 ||
                value > 2000
            ) ||
            coverage < 0.9 ||
            coverage > 1.1
          ) {
            throw new Error('invalid recording')
          }
          indices.add(recording.recordingIndex)
        }
        continue
      }
      for (const recording of values) {
        if (
          !recording ||
          Array.isArray(recording) ||
          Object.keys(recording).sort().join(',') !==
            'durationSeconds,recordingType,rrIntervalsMs' ||
          recording.recordingType !== 'rest' ||
          !Number.isInteger(recording.durationSeconds) ||
          recording.durationSeconds < 300 ||
          recording.durationSeconds > 360 ||
          !Array.isArray(recording.rrIntervalsMs) ||
          recording.rrIntervalsMs.length < (sampleEntropy ? 240 : 180) ||
          recording.rrIntervalsMs.length > (sampleEntropy ? 900 : 3600) ||
          recording.rrIntervalsMs.some(
            (value: unknown) =>
              typeof value !== 'number' ||
              !Number.isFinite(value) ||
              value < (sampleEntropy ? 300 : 250) ||
              value > 2000
          ) ||
          Math.abs(
            recording.rrIntervalsMs.reduce(
              (total: number, value: number) => total + value,
              0
            ) /
              1000 -
              recording.durationSeconds
          ) > Math.max(5, recording.durationSeconds * 0.1)
        ) {
          throw new Error('invalid recording')
        }
      }
    }
  } catch {
    rmSync(destination, { force: true })
    throw new PrivateDatasetError('private_dataset_contract_invalid')
  }
}

export async function downloadPrivateDataset(
  file: UrlFileObject,
  destination: string,
  jobId: string,
  policy: PrivateDatasetPolicy,
  environment: NodeJS.ProcessEnv = process.env
): Promise<{ bytes: number; checksum: string; sourceSnapshotSha256?: string }> {
  if (!JOB_ID.test(jobId)) {
    throw new PrivateDatasetError('private_dataset_job_id_invalid')
  }
  if (
    file.type !== 'url' ||
    file.method.toLowerCase() !== 'get' ||
    file.url !== policy.url
  ) {
    throw new PrivateDatasetError('private_dataset_url_not_allowed')
  }
  const result = await downloadVerifiedJson(
    policy.url,
    destination,
    policy.maxBytes,
    requestHeaders(file, jobId, policy, environment),
    privateDatasetHttpsAgent(policy),
    Boolean(policy.paperInsight)
  )
  if (policy.study && !result.sourceSnapshotSha256) {
    rmSync(destination, { force: true })
    throw new PrivateDatasetError('private_dataset_source_snapshot_invalid')
  }
  validateReviewedCohortInput(destination, policy)
  return result
}

export async function downloadVerifiedJson(
  url: string,
  destination: string,
  maxBytes: number,
  headers: Record<string, string>,
  httpsAgent?: HttpsAgent,
  requireReleaseSequence: boolean = false
): Promise<{ bytes: number; checksum: string; sourceSnapshotSha256?: string }> {
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 1 ||
    maxBytes > MAX_PRIVATE_DATASET_BYTES
  ) {
    throw new PrivateDatasetError('private_dataset_size_limit_invalid')
  }
  const partial = `${destination}.part`
  let responseStream: Readable | undefined
  try {
    if (existsSync(destination)) {
      throw new PrivateDatasetError('private_dataset_destination_exists')
    }
    rmSync(partial, { force: true })

    const response = await axios({
      method: 'get',
      url,
      headers,
      httpsAgent,
      responseType: 'stream',
      timeout: 30000,
      maxRedirects: 0,
      decompress: false,
      validateStatus: (status) => status === 200
    })
    responseStream = response.data
    const contentType = String(response.headers['content-type'] ?? '')
      .split(';', 1)[0]
      .trim()
      .toLowerCase()
    if (contentType !== 'application/json') {
      throw new PrivateDatasetError('private_dataset_content_type_invalid')
    }
    const contentEncoding = response.headers['content-encoding']
    if (contentEncoding && String(contentEncoding).toLowerCase() !== 'identity') {
      throw new PrivateDatasetError('private_dataset_content_encoding_invalid')
    }
    const contentLengthText = requiredHeader(
      response.headers['content-length'],
      /^(0|[1-9][0-9]*)$/,
      'private_dataset_content_length_invalid'
    )
    const declaredBytes = Number(contentLengthText)
    if (!Number.isSafeInteger(declaredBytes) || declaredBytes > maxBytes) {
      throw new PrivateDatasetError('private_dataset_too_large')
    }
    const expectedChecksum = requiredHeader(
      response.headers['x-content-sha256'],
      SHA256,
      'private_dataset_checksum_invalid'
    )
    const sourceSnapshotHeader = response.headers['x-brainstem-source-snapshot-sha256']
    const sourceSnapshotSha256 =
      sourceSnapshotHeader === undefined
        ? undefined
        : requiredHeader(
            sourceSnapshotHeader,
            SHA256,
            'private_dataset_source_snapshot_invalid'
          )
    if (requireReleaseSequence) {
      requiredHeader(
        response.headers['x-brainstem-release-sequence-sha256'],
        SHA256,
        'private_dataset_release_sequence_invalid'
      )
    }

    let bytes = 0
    const hash = createHash('sha256')
    const verifier = new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
        bytes += buffer.length
        if (bytes > maxBytes) {
          callback(new PrivateDatasetError('private_dataset_too_large'))
          return
        }
        hash.update(buffer)
        callback(null, buffer)
      }
    })
    await pipeline(
      responseStream,
      verifier,
      createWriteStream(partial, { flags: 'wx', mode: 0o600 })
    )
    if (bytes !== declaredBytes) {
      throw new PrivateDatasetError('private_dataset_length_mismatch')
    }
    const checksum = hash.digest('hex')
    if (
      !timingSafeEqual(Buffer.from(checksum, 'hex'), Buffer.from(expectedChecksum, 'hex'))
    ) {
      throw new PrivateDatasetError('private_dataset_checksum_mismatch')
    }
    renameSync(partial, destination)
    return { bytes, checksum, sourceSnapshotSha256 }
  } catch (error) {
    responseStream?.destroy()
    rmSync(partial, { force: true })
    if (error instanceof PrivateDatasetError) throw error
    throw new PrivateDatasetError('private_dataset_fetch_failed')
  }
}
