import { MetadataAlgorithm, ConsumerParameter } from '@oceanprotocol/ddo-js'
import type { BaseFileObject, StorageObject, EncryptMethod } from '../fileObject.js'
import type { AccessList } from '../AccessList.js'
export enum C2DClusterType {
  // eslint-disable-next-line no-unused-vars
  OPF_K8 = 0,
  // eslint-disable-next-line no-unused-vars
  NODE_LOCAL = 1,
  // eslint-disable-next-line no-unused-vars
  DOCKER = 2
}

export interface C2DClusterInfo {
  /** Type of cluster: K8, Node local, etc */
  type: C2DClusterType
  /** Hash of cluster.  hash(url) for remote, hash(nodeId) for local */
  hash: string
  /** Connection URI */
  connection?: any
  /** Folder for storing data */
  tempFolder?: string
}

export type ComputeResourceType = 'cpu' | 'ram' | 'disk' | any

export interface ResourceConstraint {
  id: ComputeResourceType // the resource being constrained
  min?: number // min units of this resource per unit of parent resource
  max?: number // max units of this resource per unit of parent resource
}

export interface ComputeResourcesPricingInfo {
  id: ComputeResourceType
  price: number // price per unit per minute
}

export interface ArgumentValues {
  [key: string]: string | number | boolean | any[] // Supports multiple value types
}

export interface dockerDeviceRequest {
  Driver: string
  Count?: number
  DeviceIDs: string[]
  Capabilities?: any
  Options?: any
}

// docker hw can be defined with either deviceRequests (simpler, if you have a driver), or in advanced way
// advanced way means you have to defined different params like devices, cggroups, caps, etc
export interface dockerHwInit {
  deviceRequests?: dockerDeviceRequest
  advanced?: ArgumentValues
  runtime?: string
}

export interface ComputeResource {
  id: ComputeResourceType
  description?: string
  type?: string
  kind?: string // discreet, named, etc
  total: number // total number of specific resource
  min: number // min number of resource needed for a job
  max: number // max number of resource for a job
  inUse?: number // for display purposes
  driverVersion?: string
  memoryTotal?: string
  /**
   * `nvidia` | `amd` | `intel`
   */
  platform?: string
  init?: dockerHwInit
  constraints?: ResourceConstraint[] // optional cross-resource constraints
}
export interface ComputeResourceRequest {
  id: string
  amount: number
}

export interface ComputeResourceRequestWithPrice extends ComputeResourceRequest {
  price?: number // price per unit per minute
}

export interface ComputeEnvFees {
  feeToken: string
  prices: ComputeResourcesPricingInfo[]
}
export interface ComputeEnvFeesStructure {
  [chainId: string]: ComputeEnvFees[]
}

export interface RunningPlatform {
  architecture: string
  os?: string
}

export interface ComputeAccessList {
  addresses: string[]
  accessLists: AccessList[] | null
}

export interface ComputeEnvironmentFreeOptions {
  // only if a compute env exposes free jobs
  storageExpiry?: number
  maxJobDuration?: number
  minJobDuration?: number
  maxJobs?: number // maximum number of simultaneous free jobs
  resources?: ComputeResource[]
  access: ComputeAccessList
  allowImageBuild?: boolean
}
export type ConsumerResultPolicy =
  | { mode: 'archive' }
  | {
      mode: 'singleJson'
      maxBytes: number
      resultContract?: 'brainstem.c2d-result/v1' | 'brainstem.insight-result/v1'
    }

export interface PrivateDatasetPolicy {
  analysisId:
    | 'brainstem.resting-rr-cohort-summary/v1'
    | 'brainstem.resting-hrv-methods/v1'
    | 'brainstem.resting-rr-sample-entropy/v1'
    | 'brainstem.sleep-reliability-benchmark/v1'
    | 'brainstem.overnight-heart-rate-change/v1'
    | 'brainstem.resting-hrv-repeatability/v1'
    | 'brainstem.standing-heart-rate-response/v1'
    | 'brainstem.guided-breathing-response/v1'
  url: string
  maxBytes: number
  approvedAlgorithmImage: string
  bearerTokenEnv: string
  releaseId: string
  paperInsight?: {
    algorithmVersion: '0.1.0' | '0.2.0' | '0.3.0'
    inputSchema:
      | 'brainstem.resting-hrv-methods-cohort/v1'
      | 'brainstem.resting-sample-entropy-cohort/v1'
      | 'brainstem.sleep-nightly-features-cohort/v1'
      | 'brainstem.overnight-heart-rate-change-cohort/v2'
      | 'brainstem.resting-hrv-repeatability-cohort/v1'
      | 'brainstem.standing-heart-rate-response-cohort/v1'
      | 'brainstem.guided-breathing-response-cohort/v1'
    candidateManifestSha256: string
    approvedManifestSha256: string
    referenceSha256: string | null
    evidenceTier:
      | 'E0_candidate'
      | 'E1_public_reproduced'
      | 'E2_brainstem_compatible_exploratory'
    useClass: 'methods_only'
    clinicalUse: 'prohibited'
  }
  participantValue?: {
    crabSignerAddress: string
  }
  tls?: {
    caFile: string
    clientCertificateFile: string
    clientKeyFile: string
    serverName: string
  }
}

export interface PersonalInsightPolicy {
  analysisId:
    | 'brainstem.personal-resting-heart-overview/v1'
    | 'brainstem.resting-hrv-methods/v1'
    | 'brainstem.resting-rr-sample-entropy/v1'
    | 'brainstem.sleep-baseline/v1'
    | 'brainstem.sleep-baseline/v2'
    | 'brainstem.overnight-heart-rate-change/v1'
    | 'brainstem.resting-hrv-repeatability/v1'
    | 'brainstem.standing-heart-rate-response/v1'
    | 'brainstem.guided-breathing-response/v1'
  algorithmVersion: '1.0.0' | '0.1.0' | '0.2.0'
  crabUrl: string
  approvedAlgorithmImage: string
  candidateManifestSha256: string | null
  approvedManifestSha256: string | null
  referenceSha256: string | null
  evidenceTier:
    | 'E0_candidate'
    | 'E1_public_reproduced'
    | 'E2_brainstem_compatible_exploratory'
  useClass: 'methods_only'
  clinicalUse: 'prohibited'
  bearerTokenEnv: string
  bffBearerTokenEnv: string
  ramWorkspaceRoot: string
  inputSchema:
    | 'brainstem.personal-resting-rr/v1'
    | 'brainstem.personal-resting-hrv-methods/v1'
    | 'brainstem.personal-resting-sample-entropy/v1'
    | 'brainstem.personal-sleep-baseline/v2'
    | 'brainstem.personal-sleep-nightly-features/v1'
    | 'brainstem.personal-overnight-heart-rate-change/v2'
    | 'brainstem.personal-resting-hrv-repeatability/v1'
    | 'brainstem.personal-standing-heart-rate-response/v1'
    | 'brainstem.personal-guided-breathing-response/v1'
  inputPolicy:
    | 'brainstem.personal-resting-rr/latest-16/v1'
    | 'brainstem.personal-resting-hrv-methods/latest-16/v1'
    | 'brainstem.personal-resting-sample-entropy/latest-4/v1'
    | 'brainstem.personal-sleep-baseline/latest-7/v2'
    | 'brainstem.personal-sleep-baseline/latest-distinct-9/v2'
    | 'brainstem.personal-overnight-heart-rate-change/latest-distinct-9-movement/v2'
    | 'brainstem.personal-resting-hrv-repeatability/latest-distinct-7/v1'
    | 'brainstem.personal-standing-heart-rate-response/latest-7/v1'
    | 'brainstem.personal-guided-breathing-response/protocol-6-5-0-5-0/latest-7/v1'
  resultContract: 'brainstem.c2d-result/v1' | 'brainstem.insight-result/v1'
  resultProfile:
    | 'brainstem.personal-resting-heart-overview/v1'
    | 'brainstem.resting-hrv-methods-personal/v1'
    | 'brainstem.resting-sample-entropy-personal/v1'
    | 'brainstem.sleep-baseline-personal/v1'
    | 'brainstem.sleep-baseline-personal/v2'
    | 'brainstem.overnight-heart-rate-change-personal/v2'
    | 'brainstem.resting-hrv-repeatability-personal/v1'
    | 'brainstem.standing-heart-rate-response-personal/v1'
    | 'brainstem.guided-breathing-response-personal/v1'
  audience: 'brainstem-ocean-node'
  maximumRecordings: 4 | 7 | 9 | 16
  maxInputBytes: number
  maxResultBytes: number
  maxJobDuration: number
  resources: {
    cpu: number
    ram: number
  }
  allowInsecureLocalProof?: boolean
  tls?: PrivateDatasetPolicy['tls']
}

export interface ComputeEnvironmentBaseConfig {
  description?: string // v1
  storageExpiry?: number // amount of seconds for storage
  minJobDuration?: number // min billable seconds for a paid job
  maxJobDuration?: number // max duration in seconds for a paid job
  maxJobs?: number // maximum number of simultaneous paid jobs
  fees: ComputeEnvFeesStructure
  resources?: ComputeResource[]
  access: ComputeAccessList
  free?: ComputeEnvironmentFreeOptions
  platform: RunningPlatform
  enableNetwork?: boolean // whether network is enabled for algorithm containers
  consumerResultPolicy: ConsumerResultPolicy
}

export interface ComputeRuntimes {
  [key: string]: {
    path?: string
    runtimeArgs?: string[] // Optional runtime arguments
  }
}
export interface ComputeEnvironment extends ComputeEnvironmentBaseConfig {
  id: string // v1
  configuredId?: string
  runningJobs: number
  runningfreeJobs?: number
  consumerAddress: string // v1
  queuedJobs: number
  queuedFreeJobs: number
  queMaxWaitTime: number
  queMaxWaitTimeFree: number
  runMaxWaitTime: number
  runMaxWaitTimeFree: number
}

export interface C2DEnvironmentConfig {
  id?: string
  description?: string
  storageExpiry?: number
  minJobDuration?: number
  maxJobDuration?: number
  maxJobs?: number
  fees?: ComputeEnvFeesStructure
  access?: ComputeAccessList
  free?: ComputeEnvironmentFreeOptions
  resources?: ComputeResource[]
  enableNetwork?: boolean // whether network is enabled for algorithm containers
  consumerResultPolicy: ConsumerResultPolicy
  privateDataset?: PrivateDatasetPolicy
  personalInsight?: PersonalInsightPolicy
}

export type ImageScanSeverity = 'UNKNOWN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface C2DDockerConfig {
  socketPath: string
  protocol: string
  host: string
  port: number
  caPath: string
  certPath: string
  keyPath: string
  imageRetentionDays?: number // Default: 7 days
  imageCleanupInterval?: number // Default: 86400 seconds (24 hours)
  paymentClaimInterval?: number // Default: 3600 seconds (1 hours)
  scanImages?: boolean
  scanImageRejectSeverities?: ImageScanSeverity[]
  scanImageDBUpdateInterval?: number // Default: 12 hours
  environments: C2DEnvironmentConfig[]
}

export type ComputeResultType =
  | 'imageLog'
  | 'algorithmLog'
  | 'output'
  | 'configurationLog'
  | 'publishLog'

export interface ComputeResult {
  filename: string
  filesize: number
  type: ComputeResultType
  index?: number
}

export type DBComputeJobMetadata = {
  [key: string]: string | number | boolean
}

export interface ComputeJobTerminationDetails {
  OOMKilled: boolean
  exitCode: number
}

export type ComputeSettlementStatus =
  | 'not_charged'
  | 'charged'
  | 'refunded'
  | 'refund_required'
  | 'unknown'

export interface ComputeSettlement {
  status: ComputeSettlementStatus
  amount: number
  chainId?: number
  token?: string
  transactionHash?: string
}

export interface ParticipantValueCommitment {
  schema: 'brainstem.participant-value-commitment/v1'
  computeReceiptSha256: string
  valuePolicy: 'brainstem.equal-cohort-contribution/v1'
  participantCount: number | null
  amountPerParticipant: number
  entitlementSetSha256: string
  committedAt: string
  signature: string
}

export interface ParticipantValueReceipt {
  schema: 'brainstem.compute-receipt/v1'
  jobIdHash: string
  inputSha256: string
  resultSha256: string
  resultSchema: 'brainstem.c2d-result/v1'
  resultStatus: 'complete' | 'insufficient_data'
  algorithmImageDigest: string
  completedAt: string
}

export interface ParticipantValueRequest {
  receipt: ParticipantValueReceipt
  receiptSignature: string
}

export interface ParticipantValueProof {
  receipt: ParticipantValueReceipt
  receiptSignature: string
  commitment: ParticipantValueCommitment
}

export interface ComputeJob {
  owner: string
  did?: string
  jobId: string
  dateCreated: string
  dateFinished: string
  status: number
  statusText: string
  results: ComputeResult[]
  inputDID?: string[]
  algoDID?: string
  maxJobDuration?: number
  agreementId?: string
  environment?: string
  metadata?: DBComputeJobMetadata
  terminationDetails?: ComputeJobTerminationDetails
  settlement?: ComputeSettlement
  participantValue?: ParticipantValueProof
  participantValueStatus?: 'committed' | 'rejected'
  queueMaxWaitTime: number // max time in seconds a job can wait in the queue before being started
}

export interface ComputeOutputEncryption {
  encryptMethod: EncryptMethod.AES // in future we will support more ciphers
  key: string // AES symetric key
}

export interface ComputeOutput {
  remoteStorage?: StorageObject
  encryption?: ComputeOutputEncryption
}

export interface ComputeAsset {
  fileObject?: BaseFileObject
  documentId?: string
  serviceId?: string
  transferTxId?: string
  userdata?: { [key: string]: any }
}
export interface ExtendedMetadataAlgorithm extends MetadataAlgorithm {
  container: {
    // retain existing properties
    entrypoint: string
    image: string
    tag: string
    checksum: string
    dockerfile?: string // optional
    additionalDockerFiles?: { [key: string]: any }
    consumerParameters?: ConsumerParameter[]
  }
}
export interface ComputeAlgorithm {
  documentId?: string
  serviceId?: string
  fileObject?: BaseFileObject
  meta?: ExtendedMetadataAlgorithm
  transferTxId?: string
  algocustomdata?: { [key: string]: any }
  userdata?: { [key: string]: any }
  envs?: { [key: string]: any }
}

export interface AlgoChecksums {
  files: string
  container: string
  serviceId?: string
}

export interface DBComputeJobPayment {
  chainId: number
  token: string
  lockTx: string
  claimTx: string
  cancelTx: string
  cost: number
}

export interface DBComputeResultValidation {
  contract: 'brainstem.c2d-result/v1' | 'brainstem.insight-result/v1'
  status: 'complete' | 'insufficient_data' | 'failed'
  billable: boolean
  algorithmVersion?: string
  algorithmImageDigest?: string
  datasetSchemaVersion?: string
}

export type DBPrivateResultCleanupState = 'pending' | 'complete' | 'failed'

export interface DBPrivateResultRetention {
  cleanupState: DBPrivateResultCleanupState
  inputChecksum?: string
  resultChecksum?: string
  algorithmImageDigest: string
  retainedAt?: number
  expiresAt: number
  resultDeletedAt?: number
  cleanupErrorCode?: 'private_cleanup_failed'
}

export type DBSettlementDecision = 'charge' | 'release'
export type DBSettlementStatus =
  | 'prepared'
  | 'broadcast'
  | 'charged'
  | 'not_charged'
  | 'refunded'
  | 'refund_required'
  | 'unknown'

export interface DBSettlementIntent {
  settlementKey: string
  jobId: string
  jobIdHash: string
  chainId: number
  escrowAddress: string
  token: string
  payer: string
  decision: DBSettlementDecision
  amount: number
  reason: string
  preparedBlock: number
  status: DBSettlementStatus
  transactionHash?: string
  rawTransaction?: string
  settledAmount?: number
  receiptBlock?: number
  createdAt: number
  updatedAt: number
}

// this is the internal structure
export interface DBComputeJob extends ComputeJob {
  clusterHash: string
  configlogURL: string
  publishlogURL: string
  algologURL: string
  outputsURL: string
  stopRequested: boolean
  algorithm: ComputeAlgorithm
  assets: ComputeAsset[]
  isRunning: boolean
  isStarted: boolean
  containerImage: string
  isFree: boolean
  algoStartTimestamp: string
  algoStopTimestamp: string
  resources: ComputeResourceRequestWithPrice[]
  payment?: DBComputeJobPayment
  resultValidation?: DBComputeResultValidation
  participantValueRequired?: boolean
  participantValueRequest?: ParticipantValueRequest
  privateResultRetention?: DBPrivateResultRetention
  privateInputChecksum?: string
  personalInsightRunId?: string
  personalInsightHistoryId?: string
  personalInsightState?: 'pending' | 'complete' | 'rejected'
  metadata?: DBComputeJobMetadata
  additionalViewers?: string[] // addresses of additional addresses that can get results
  algoDuration: number // duration of the job in seconds
  encryptedDockerRegistryAuth?: string
  output?: string // this is always an ECIES encrypted string, that decodes to ComputeOutput interface
  jobIdHash: string
  buildStartTimestamp?: string
  buildStopTimestamp?: string
}

// make sure we keep them both in sync
export enum C2DStatusNumber {
  // eslint-disable-next-line no-unused-vars
  JobStarted = 0,
  // eslint-disable-next-line no-unused-vars
  JobQueued = 1,
  // eslint-disable-next-line no-unused-vars
  JobQueuedExpired = 2,
  // eslint-disable-next-line no-unused-vars
  PullImage = 10,
  // eslint-disable-next-line no-unused-vars
  PullImageFailed = 11,
  // eslint-disable-next-line no-unused-vars
  BuildImage = 12,
  // eslint-disable-next-line no-unused-vars
  BuildImageFailed = 13,
  // eslint-disable-next-line no-unused-vars
  VulnerableImage = 14,
  // eslint-disable-next-line no-unused-vars
  ImageScanFailed = 15,
  // eslint-disable-next-line no-unused-vars
  ConfiguringVolumes = 20,
  // eslint-disable-next-line no-unused-vars
  VolumeCreationFailed = 21,
  // eslint-disable-next-line no-unused-vars
  ContainerCreationFailed = 22,
  // eslint-disable-next-line no-unused-vars
  Provisioning = 30,
  // eslint-disable-next-line no-unused-vars
  DataProvisioningFailed = 31,
  // eslint-disable-next-line no-unused-vars
  AlgorithmProvisioningFailed = 32,
  // eslint-disable-next-line no-unused-vars
  DataUploadFailed = 33,
  // eslint-disable-next-line no-unused-vars
  RunningAlgorithm = 40,
  // eslint-disable-next-line no-unused-vars
  AlgorithmFailed = 41,
  // eslint-disable-next-line no-unused-vars
  DiskQuotaExceeded = 42,
  // eslint-disable-next-line no-unused-vars
  FilteringResults = 50,
  // eslint-disable-next-line no-unused-vars
  PublishingResults = 60,
  // eslint-disable-next-line no-unused-vars
  ResultsFetchFailed = 61,
  // eslint-disable-next-line no-unused-vars
  ResultsUploadFailed = 62,
  // eslint-disable-next-line no-unused-vars
  JobFinished = 70,
  // eslint-disable-next-line no-unused-vars
  JobSettle = 71
}
export enum C2DStatusText {
  // eslint-disable-next-line no-unused-vars
  JobStarted = 'Job started',
  // eslint-disable-next-line no-unused-vars
  JobQueued = 'Job queued',
  // eslint-disable-next-line no-unused-vars
  JobQueuedExpired = 'Job expired in queue',
  // eslint-disable-next-line no-unused-vars
  PullImage = 'Pulling algorithm image',
  // eslint-disable-next-line no-unused-vars
  PullImageFailed = 'Pulling algorithm image failed',
  // eslint-disable-next-line no-unused-vars
  BuildImage = 'Building algorithm image',
  // eslint-disable-next-line no-unused-vars
  BuildImageFailed = 'Building algorithm image failed',
  // eslint-disable-next-line no-unused-vars
  VulnerableImage = 'Image has vulnerabilities',
  // eslint-disable-next-line no-unused-vars
  ImageScanFailed = 'Image vulnerability scan failed',
  // eslint-disable-next-line no-unused-vars
  ConfiguringVolumes = 'Configuring volumes',
  // eslint-disable-next-line no-unused-vars
  VolumeCreationFailed = 'Volume creation failed',
  // eslint-disable-next-line no-unused-vars
  ContainerCreationFailed = 'Container creation failed',
  // eslint-disable-next-line no-unused-vars
  Provisioning = 'Provisioning data',
  // eslint-disable-next-line no-unused-vars
  DataProvisioningFailed = 'Data provisioning failed',
  // eslint-disable-next-line no-unused-vars
  AlgorithmProvisioningFailed = 'Algorithm provisioning failed',
  // eslint-disable-next-line no-unused-vars
  DataUploadFailed = 'Data upload to container failed',
  // eslint-disable-next-line no-unused-vars
  RunningAlgorithm = 'Running algorithm ',
  // eslint-disable-next-line no-unused-vars
  AlgorithmFailed = 'Failed to run algorithm',
  // eslint-disable-next-line no-unused-vars
  DiskQuotaExceeded = 'Error: disk quota exceeded',
  // eslint-disable-next-line no-unused-vars
  FilteringResults = 'Filtering results',
  // eslint-disable-next-line no-unused-vars
  PublishingResults = 'Publishing results',
  // eslint-disable-next-line no-unused-vars
  ResultsFetchFailed = 'Failed to get outputs folder from container',
  // eslint-disable-next-line no-unused-vars
  ResultsUploadFailed = 'Failed to upload results to storage',
  // eslint-disable-next-line no-unused-vars
  JobFinished = 'Job finished',
  // eslint-disable-next-line no-unused-vars
  JobSettle = 'Job settling'
}
