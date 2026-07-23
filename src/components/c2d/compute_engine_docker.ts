/* eslint-disable security/detect-non-literal-fs-filename */
import { Readable, PassThrough } from 'stream'
import os from 'os'
import path from 'path'
import {
  C2DStatusNumber,
  C2DStatusText,
  DBComputeJobMetadata
} from '../../@types/C2D/C2D.js'
import type {
  C2DClusterInfo,
  ComputeEnvironment,
  ComputeAlgorithm,
  ComputeOutput,
  ComputeAsset,
  ComputeJob,
  DBComputeJob,
  DBComputeJobPayment,
  ComputeResult,
  RunningPlatform,
  ComputeEnvFeesStructure,
  ComputeResourceRequest,
  ComputeEnvFees,
  ComputeResource,
  C2DEnvironmentConfig,
  ComputeResourcesPricingInfo,
  ConsumerResultPolicy,
  PrivateDatasetPolicy,
  ImageScanSeverity,
  DBSettlementIntent,
  DBSettlementStatus
} from '../../@types/C2D/C2D.js'
import { BASE_CHAIN_ID, USDC_TOKEN_ADDRESS_BASE } from '../../utils/config.js'
import { C2DEngine } from './compute_engine_base.js'
import { C2DDatabase } from '../database/C2DDatabase.js'
import { Escrow } from '../core/utils/escrow.js'
import { create256Hash } from '../../utils/crypt.js'
import { Storage } from '../storage/index.js'
import Dockerode from 'dockerode'
import type { ContainerCreateOptions, HostConfig, VolumeCreateOptions } from 'dockerode'
import * as tar from 'tar'
import * as tarStream from 'tar-stream'
import {
  createWriteStream,
  existsSync,
  mkdirSync,
  chmodSync,
  rmSync,
  writeFileSync,
  appendFileSync,
  statSync,
  statfsSync,
  createReadStream,
  renameSync
} from 'fs'
import { pipeline } from 'node:stream/promises'
import { CORE_LOGGER } from '../../utils/logging/common.js'
import { ENVIRONMENT_VARIABLES } from '../../utils/constants.js'
import { AssetUtils } from '../../utils/asset.js'
import { FindDdoHandler } from '../core/handler/ddoHandler.js'
import { OceanNode } from '../../OceanNode.js'
import { KeyManager } from '../KeyManager/index.js'
import { decryptFilesObject, omitDBComputeFieldsFromComputeJob } from './index.js'
import {
  readSingleJsonResultArchive,
  validateConsumerResultContract
} from './consumerResult.js'
import {
  decideSettlement,
  projectSettlement,
  sameSettlementIntent,
  SETTLEMENT_JOB_STATUSES
} from './settlement.js'
import { evaluateTrivyReport } from './imageScan.js'
import { ValidateParams } from '../httpRoutes/validateCommands.js'
import { Service } from '@oceanprotocol/ddo-js'
import { getOceanTokenAddressForChain } from '../../utils/address.js'
import { dockerRegistryAuth, OceanNodeConfig } from '../../@types/OceanNode.js'
import { EncryptMethod, UrlFileObject } from '../../@types/fileObject.js'
import { getAddress, ZeroAddress } from 'ethers'
import { AccessList } from '../../@types/AccessList.js'
import {
  assertPrivateDatasetConfiguration,
  assertPrivateDatasetJob,
  downloadPrivateDataset
} from './privateDataset.js'

const C2D_CONTAINER_UID = 1000
const C2D_CONTAINER_GID = 1000

const trivyImage = 'aquasec/trivy:0.69.3' // Use pinned versions for safety
const MAX_TRIVY_REPORT_BYTES = 10 * 1024 * 1024

export function createComputeEnvironmentId(
  clusterHash: string,
  fees: ComputeEnvFeesStructure,
  resultPolicy: ConsumerResultPolicy,
  suffix: string,
  privateDataset?: PrivateDatasetPolicy
): string {
  return (
    clusterHash +
    '-' +
    create256Hash(
      JSON.stringify(fees) +
        JSON.stringify(resultPolicy) +
        (privateDataset ? JSON.stringify(privateDataset) : '') +
        suffix
    )
  )
}

export class C2DEngineDocker extends C2DEngine {
  private envs: ComputeEnvironment[] = []
  private privateDatasetPolicies: Map<string, PrivateDatasetPolicy> = new Map()

  public docker: Dockerode
  private cronTimer: any
  private cronTime: number = 2000
  private jobImageSizes: Map<string, number> = new Map()
  private isInternalLoopRunning: boolean = false
  private imageCleanupInitialTimer: NodeJS.Timeout | null = null
  private imageCleanupTimer: NodeJS.Timeout | null = null
  private paymentClaimInitialTimer: NodeJS.Timeout | null = null
  private paymentClaimTimer: NodeJS.Timeout | null = null
  private static isPaymentClaimRunning: boolean = false
  private scanDBUpdateInitialTimer: NodeJS.Timeout | null = null
  private scanDBUpdateTimer: NodeJS.Timeout | null = null
  private static DEFAULT_DOCKER_REGISTRY = 'https://registry-1.docker.io'
  private retentionDays: number
  private cleanupInterval: number
  private paymentClaimInterval: number
  private scanImages: boolean
  private scanImageRejectSeverities: ImageScanSeverity[]
  private scanImageDBUpdateInterval: number
  private trivyCachePath: string
  private cpuAllocations: Map<string, number[]> = new Map()
  private envCpuCoresMap: Map<string, number[]> = new Map()
  private activeBuildAborts: Map<string, AbortController> = new Map()

  public constructor(
    clusterConfig: C2DClusterInfo,
    db: C2DDatabase,
    escrow: Escrow,
    keyManager: KeyManager,
    config: OceanNodeConfig
  ) {
    super(clusterConfig, db, escrow, keyManager, config)

    this.docker = null
    if (clusterConfig.connection.socketPath) {
      try {
        this.docker = new Dockerode({ socketPath: clusterConfig.connection.socketPath })
      } catch (e) {
        CORE_LOGGER.error('Could not create Docker container: ' + e.message)
      }
    }
    this.retentionDays = clusterConfig.connection.imageRetentionDays || 7
    this.cleanupInterval = clusterConfig.connection.imageCleanupInterval
    this.paymentClaimInterval = clusterConfig.connection.paymentClaimInterval || 3600 // 1 hour
    this.scanImages = clusterConfig.connection.scanImages || false // default is not to scan images for now, until it's prod ready
    this.scanImageRejectSeverities =
      clusterConfig.connection.scanImageRejectSeverities || []
    if (this.scanImages && this.scanImageRejectSeverities.length === 0) {
      throw new Error(
        'scanImageRejectSeverities must be configured when image scanning is enabled'
      )
    }
    this.scanImageDBUpdateInterval = clusterConfig.connection.scanImageDBUpdateInterval

    if (
      clusterConfig.connection.protocol &&
      clusterConfig.connection.host &&
      clusterConfig.connection.port
    ) {
      try {
        this.docker = new Dockerode({
          protocol: clusterConfig.connection.protocol,
          host: clusterConfig.connection.host,
          port: clusterConfig.connection.port
        })
      } catch (e) {
        CORE_LOGGER.error('Could not create Docker container: ' + e.message)
      }
    }
    // trivy cache is the same for all engines
    this.trivyCachePath = path.join(
      process.cwd(),
      this.getC2DConfig().tempFolder,
      'trivy_cache'
    )
    try {
      if (!existsSync(this.getStoragePath()))
        mkdirSync(this.getStoragePath(), { recursive: true })
      if (this.scanImages && !existsSync(this.trivyCachePath))
        mkdirSync(this.trivyCachePath, { recursive: true })
    } catch (e) {
      CORE_LOGGER.error(
        'Could not create Docker container temporary folders: ' + e.message
      )
    }

    // envs are build on start function
  }

  private processFeesForEnvironment(
    rawFees: ComputeEnvFeesStructure | undefined,
    supportedChains: number[]
  ): ComputeEnvFeesStructure | null {
    if (!rawFees || Object.keys(rawFees).length === 0) return null
    let fees: ComputeEnvFeesStructure = null
    for (const feeChain of Object.keys(rawFees)) {
      if (!supportedChains.includes(parseInt(feeChain))) continue
      if (fees === null) fees = {}
      if (!(feeChain in fees)) fees[feeChain] = []
      const tmpFees: ComputeEnvFees[] = []
      for (const feeEntry of rawFees[feeChain]) {
        if (!feeEntry.prices || feeEntry.prices.length === 0) {
          CORE_LOGGER.error(
            `Unable to find prices for fee ${JSON.stringify(feeEntry)} on chain ${feeChain}`
          )
          continue
        }
        if (!feeEntry.feeToken) {
          const tokenAddress = getOceanTokenAddressForChain(parseInt(feeChain))
          if (tokenAddress) {
            feeEntry.feeToken = tokenAddress
            tmpFees.push(feeEntry)
          } else {
            CORE_LOGGER.error(
              `Unable to find Ocean token address for chain ${feeChain} and no custom token provided`
            )
          }
        } else {
          tmpFees.push(feeEntry)
        }
      }
      fees[feeChain] = tmpFees
    }
    return fees
  }

  public getStoragePath(): string {
    return this.getC2DConfig().tempFolder + this.getC2DConfig().hash
  }

  private createBenchmarkEnvironment(sysinfo: any, envConfig: any): void {
    const ramGB = this.physicalLimits.get('ram') || 0
    const physicalDiskGB = this.physicalLimits.get('disk') || 0

    const gpuMap = new Map<string, ComputeResource>()
    for (const env of envConfig.environments) {
      if (env.resources) {
        for (const res of env.resources) {
          if (res.id !== 'cpu' && res.id !== 'ram' && res.id !== 'disk') {
            if (!gpuMap.has(res.id)) {
              gpuMap.set(res.id, res)
            }
          }
        }
      }
    }
    const gpuResources: ComputeResource[] = Array.from(gpuMap.values())

    const benchmarkPrices: ComputeResourcesPricingInfo[] =
      gpuResources.length > 0 ? [{ id: gpuResources[0].id, price: 1 }] : []

    const benchmarkFees: ComputeEnvFeesStructure = {
      [BASE_CHAIN_ID]: [{ feeToken: USDC_TOKEN_ADDRESS_BASE, prices: benchmarkPrices }]
    }

    const benchmarkEnv: C2DEnvironmentConfig = {
      description: 'Auto-generated benchmark environment',
      storageExpiry: 604800,
      maxJobDuration: 180,
      minJobDuration: 0,
      resources: [
        { id: 'cpu', total: sysinfo.NCPU, min: 1, max: sysinfo.NCPU },
        { id: 'ram', total: ramGB, min: 1, max: ramGB },
        { id: 'disk', total: physicalDiskGB, min: 0, max: physicalDiskGB },
        ...gpuResources
      ],
      access: {
        addresses: [],
        accessLists: [
          { [BASE_CHAIN_ID]: [getAddress('0xcb7Db55Ca9Aa9C3b25F5Bc266da63317fa02086a')] }
        ]
      },
      fees: benchmarkFees,
      enableNetwork: true,
      consumerResultPolicy: { mode: 'archive' }
    }

    envConfig.environments.push(benchmarkEnv)
  }

  public override async start() {
    const config = this.getConfig()
    const envConfig = await this.getC2DConfig().connection
    if (!envConfig?.environments?.length) {
      CORE_LOGGER.warn(
        `Skipping C2D Engine ${this.getC2DConfig().hash}: no environments configured`
      )
      return
    }
    let sysinfo = null
    try {
      sysinfo = await this.docker.info()
    } catch (e) {
      CORE_LOGGER.error('Could not get docker info: ' + e.message)
      // since we cannot connect to docker, we cannot start the engine -> no envs
      return
    }

    this.physicalLimits.set('cpu', sysinfo.NCPU)
    this.physicalLimits.set('ram', Math.floor(sysinfo.MemTotal / 1024 / 1024 / 1024))
    try {
      const diskStats = statfsSync(this.getC2DConfig().tempFolder)
      const diskGB = Math.floor((diskStats.bsize * diskStats.blocks) / 1024 / 1024 / 1024)
      this.physicalLimits.set('disk', diskGB)
    } catch (e) {
      CORE_LOGGER.warn('Could not detect physical disk size: ' + e.message)
    }

    // Determine supported chains
    const supportedChains: number[] = []
    if (config.supportedNetworks) {
      for (const chain of Object.keys(config.supportedNetworks)) {
        supportedChains.push(parseInt(chain))
      }
    }

    const platform: RunningPlatform = {
      architecture: sysinfo.Architecture,
      os: sysinfo.OSType
    }
    const consumerAddress = this.getKeyManager().getEthAddress()

    if (config.enableBenchmark) {
      if (supportedChains.includes(parseInt(BASE_CHAIN_ID))) {
        this.createBenchmarkEnvironment(sysinfo, envConfig)
      } else {
        CORE_LOGGER.warn(
          `Skipping benchmark environment: Base chain (${BASE_CHAIN_ID}) is not in supportedNetworks`
        )
      }
    }

    for (let envIdx = 0; envIdx < envConfig.environments.length; envIdx++) {
      const envDef: C2DEnvironmentConfig = envConfig.environments[envIdx]

      const fees = this.processFeesForEnvironment(envDef.fees, supportedChains)

      const envResources: ComputeResource[] = []
      const cpuResources = {
        id: 'cpu',
        type: 'cpu',
        total: sysinfo.NCPU,
        max: sysinfo.NCPU,
        min: 1,
        description: os.cpus()[0].model
      }
      const ramResources = {
        id: 'ram',
        type: 'ram',
        total: Math.floor(sysinfo.MemTotal / 1024 / 1024 / 1024),
        max: Math.floor(sysinfo.MemTotal / 1024 / 1024 / 1024),
        min: 1
      }
      const physicalDiskGB = this.physicalLimits.get('disk') || 0
      const diskResources = {
        id: 'disk',
        type: 'disk',
        total: physicalDiskGB,
        max: physicalDiskGB,
        min: 0
      }

      if (envDef.resources) {
        for (const res of envDef.resources) {
          // allow user to add other resources
          if (res.id === 'cpu') {
            if (res.total) cpuResources.total = res.total
            if (res.max) cpuResources.max = res.max
            if (res.min) cpuResources.min = res.min
          }
          if (res.id === 'ram') {
            if (res.total) ramResources.total = res.total
            if (res.max) ramResources.max = res.max
            if (res.min) ramResources.min = res.min
          }
          if (res.id === 'disk') {
            if (res.total) diskResources.total = res.total
            if (res.max) diskResources.max = res.max
            if (res.min !== undefined) diskResources.min = res.min
          }

          if (res.id !== 'cpu' && res.id !== 'ram' && res.id !== 'disk') {
            if (!res.max) res.max = res.total
            if (!res.min) res.min = 0
            envResources.push(res)
          }
        }
      }
      envResources.push(cpuResources)
      envResources.push(ramResources)
      envResources.push(diskResources)

      const env: ComputeEnvironment = {
        id: '',
        runningJobs: 0,
        consumerAddress,
        platform,
        access: envDef.access || { addresses: [], accessLists: null },
        fees,
        resources: envResources,
        queuedJobs: 0,
        queuedFreeJobs: 0,
        queMaxWaitTime: 0,
        queMaxWaitTimeFree: 0,
        runMaxWaitTime: 0,
        runMaxWaitTimeFree: 0,
        enableNetwork: envDef.enableNetwork,
        consumerResultPolicy: envDef.consumerResultPolicy
      }

      if (envDef.storageExpiry !== undefined) env.storageExpiry = envDef.storageExpiry
      if (envDef.minJobDuration !== undefined) env.minJobDuration = envDef.minJobDuration
      if (envDef.maxJobDuration !== undefined) env.maxJobDuration = envDef.maxJobDuration
      if (envDef.maxJobs !== undefined) env.maxJobs = envDef.maxJobs
      if (envDef.description !== undefined) env.description = envDef.description

      // Free tier config for this environment
      if (envDef.free) {
        env.free = {
          access: envDef.free.access || { addresses: [], accessLists: null }
        }
        if (envDef.free.storageExpiry !== undefined)
          env.free.storageExpiry = envDef.free.storageExpiry
        if (envDef.free.minJobDuration !== undefined)
          env.free.minJobDuration = envDef.free.minJobDuration
        if (envDef.free.maxJobDuration !== undefined)
          env.free.maxJobDuration = envDef.free.maxJobDuration
        if (envDef.free.maxJobs !== undefined) env.free.maxJobs = envDef.free.maxJobs
        if (envDef.free.resources) env.free.resources = envDef.free.resources
        if (envDef.free.allowImageBuild !== undefined)
          env.free.allowImageBuild = envDef.free.allowImageBuild
      }

      const envIdSuffix = envDef.id || String(envIdx)
      env.id = createComputeEnvironmentId(
        this.getC2DConfig().hash,
        env.fees,
        env.consumerResultPolicy,
        envIdSuffix,
        envDef.privateDataset
      )

      if (envDef.privateDataset) {
        assertPrivateDatasetConfiguration(envDef.privateDataset)
        this.privateDatasetPolicies.set(env.id, envDef.privateDataset)
      }

      this.envs.push(env)
      CORE_LOGGER.info(
        `Engine ${this.getC2DConfig().hash}: created environment ${env.id} (index=${envIdx}, resources=${envResources.map((r) => r.id).join(',')})`
      )
    }

    const physicalCpuCount = this.physicalLimits.get('cpu') || 0
    let cpuOffset = 0
    for (const env of this.envs) {
      const cpuRes = this.getResource(env.resources ?? [], 'cpu')
      if (cpuRes && cpuRes.total > 0) {
        let isBenchmarkEnv = false
        if (env.access?.accessLists) {
          const baseAccessList = env.access?.accessLists?.[0] as AccessList
          if (baseAccessList && baseAccessList[BASE_CHAIN_ID]) {
            isBenchmarkEnv = baseAccessList[BASE_CHAIN_ID].includes(
              getAddress('0xcb7Db55Ca9Aa9C3b25F5Bc266da63317fa02086a')
            )
          }
        }

        if (isBenchmarkEnv) {
          const total = physicalCpuCount > 0 ? physicalCpuCount : cpuRes.total
          const cores = Array.from({ length: total }, (_, i) => i)
          this.envCpuCoresMap.set(env.id, cores)
          CORE_LOGGER.info(
            `CPU affinity: benchmark environment ${env.id} cores 0-${cores[cores.length - 1]}`
          )
        } else {
          const cores = Array.from({ length: cpuRes.total }, (_, i) => cpuOffset + i)
          this.envCpuCoresMap.set(env.id, cores)
          CORE_LOGGER.info(
            `CPU affinity: environment ${env.id} cores ${cores[0]}-${cores[cores.length - 1]}`
          )
          cpuOffset += cpuRes.total
        }
      }
    }

    // Rebuild CPU allocations from running containers (handles node restart)
    await this.rebuildCpuAllocations()

    // only now set the timer
    if (!this.cronTimer) {
      this.setNewTimer()
    }
    this.startCrons()
  }

  public startCrons() {
    if (!this.docker) {
      CORE_LOGGER.debug('Docker not available, skipping crons')
      return
    }

    // Start image cleanup timer
    if (this.cleanupInterval) {
      if (this.imageCleanupInitialTimer || this.imageCleanupTimer) {
        return // Already running
      }
      // Run initial cleanup after a short delay
      this.imageCleanupInitialTimer = setTimeout(() => {
        this.imageCleanupInitialTimer = null
        this.cleanupOldImages().catch((e) => {
          CORE_LOGGER.error(`Initial image cleanup failed: ${e.message}`)
        })
      }, 60000) // Wait 1 minute after start

      // Set up periodic cleanup
      this.imageCleanupTimer = setInterval(() => {
        this.cleanupOldImages().catch((e) => {
          CORE_LOGGER.error(`Periodic image cleanup failed: ${e.message}`)
        })
      }, this.cleanupInterval * 1000)

      CORE_LOGGER.info(
        `Image cleanup timer started (interval: ${this.cleanupInterval / 60} minutes)`
      )
    }
    // start payments cron
    if (this.paymentClaimInterval) {
      if (this.paymentClaimInitialTimer || this.paymentClaimTimer) {
        return // Already running
      }

      // Run initial cleanup after a short delay
      this.paymentClaimInitialTimer = setTimeout(() => {
        this.paymentClaimInitialTimer = null
        this.claimPayments().catch((e) => {
          CORE_LOGGER.error(`Initial payments claim failed: ${e.message}`)
        })
      }, 60000) // Wait 1 minute after start

      // Set up periodic cleanup
      this.paymentClaimTimer = setInterval(() => {
        this.claimPayments().catch((e) => {
          CORE_LOGGER.error(`Periodic payments claim failed: ${e.message}`)
        })
      }, this.paymentClaimInterval * 1000)

      CORE_LOGGER.info(
        `Payments claim timer started (interval: ${this.paymentClaimInterval / 60} minutes)`
      )
    }
    // scan db updater cron
    if (this.scanImages && this.scanImageDBUpdateInterval) {
      if (this.scanDBUpdateInitialTimer || this.scanDBUpdateTimer) {
        return // Already running
      }

      // Run initial db cache
      this.scanDBUpdateInitialTimer = setTimeout(() => {
        this.scanDBUpdateInitialTimer = null
        this.scanDBUpdate().catch((e) => {
          CORE_LOGGER.error(`scan DB Update Initial failed: ${e.message}`)
        })
      }, 30000) // Wait 30 seconds

      // Set up periodic cleanup
      this.scanDBUpdateTimer = setInterval(() => {
        this.scanDBUpdate().catch((e) => {
          CORE_LOGGER.error(`Periodic scan DB update failed: ${e.message}`)
        })
      }, this.scanImageDBUpdateInterval * 1000)

      CORE_LOGGER.info(
        `scan DB update timer started (interval: ${this.scanImageDBUpdateInterval / 60} minutes)`
      )
    }
  }

  public override stop(): Promise<void> {
    // Clear the timer and reset the flag
    if (this.cronTimer) {
      clearTimeout(this.cronTimer)
      this.cronTimer = null
    }
    this.isInternalLoopRunning = false
    // Stop image cleanup timer
    if (this.imageCleanupInitialTimer) {
      clearTimeout(this.imageCleanupInitialTimer)
      this.imageCleanupInitialTimer = null
      CORE_LOGGER.debug('Initial image cleanup timer stopped')
    }
    if (this.imageCleanupTimer) {
      clearInterval(this.imageCleanupTimer)
      this.imageCleanupTimer = null
      CORE_LOGGER.debug('Image cleanup timer stopped')
    }
    if (this.paymentClaimInitialTimer) {
      clearTimeout(this.paymentClaimInitialTimer)
      this.paymentClaimInitialTimer = null
      CORE_LOGGER.debug('Initial payment claim timer stopped')
    }
    if (this.paymentClaimTimer) {
      clearInterval(this.paymentClaimTimer)
      this.paymentClaimTimer = null
      CORE_LOGGER.debug('Payment claim timer stopped')
    }
    if (this.scanDBUpdateInitialTimer) {
      clearTimeout(this.scanDBUpdateInitialTimer)
      this.scanDBUpdateInitialTimer = null
      CORE_LOGGER.debug('Initial scan database update timer stopped')
    }
    if (this.scanDBUpdateTimer) {
      clearInterval(this.scanDBUpdateTimer)
      this.scanDBUpdateTimer = null
      CORE_LOGGER.debug('Scan database update timer stopped')
    }
    return Promise.resolve()
  }

  public async updateImageUsage(image: string): Promise<void> {
    try {
      await this.db.updateImage(image)
    } catch (e) {
      CORE_LOGGER.error(`Failed to update image usage for ${image}: ${e.message}`)
    }
  }

  private async claimPayments(): Promise<void> {
    if (C2DEngineDocker.isPaymentClaimRunning) return
    C2DEngineDocker.isPaymentClaimRunning = true
    try {
      const currentTimestamp = BigInt(Math.floor(Date.now() / 1000))
      const envIds = this.envs.map((env) => env.id)
      const jobs = await this.db.getJobsByStatus(envIds, SETTLEMENT_JOB_STATUSES)
      CORE_LOGGER.info(`ClaimPayments: got ${jobs.length} jobs to reconcile`)

      const providerAddress = this.getKeyManager().getEthAddress()
      const chains = new Set(
        jobs.flatMap((job) => (job.payment?.token ? [job.payment.chainId] : []))
      )
      const locksByChain = new Map<number, any[] | null>()
      for (const chain of chains) {
        try {
          locksByChain.set(
            chain,
            await this.escrow.getLocks(chain, ZeroAddress, ZeroAddress, providerAddress)
          )
        } catch (error) {
          CORE_LOGGER.error(`Failed to get locks for chain ${chain}: ${error.message}`)
          locksByChain.set(chain, null)
        }
      }

      for (const job of jobs) {
        if (job.isFree || !job.payment) {
          await this.finishJobWithoutPayment(job)
          continue
        }
        const chainLocks = locksByChain.get(job.payment.chainId)
        if (chainLocks === null || chainLocks === undefined) continue
        try {
          await this.reconcileJobSettlement(job, chainLocks, currentTimestamp)
        } catch (error) {
          CORE_LOGGER.error(
            `Failed to reconcile settlement for job ${job.jobId}: ${error.message}`
          )
        }
      }

      const envChains = new Set<number>()
      const knownJobHashes = new Set(
        jobs
          .filter((job) => job.payment && job.jobIdHash)
          .map((job) => BigInt(job.jobIdHash).toString())
      )
      for (const env of this.envs) {
        for (const chain of Object.keys(env.fees ?? {})) envChains.add(Number(chain))
      }
      for (const chain of envChains) {
        await this.cleanUpUnknownLocks(String(chain), currentTimestamp, knownJobHashes)
      }
    } finally {
      C2DEngineDocker.isPaymentClaimRunning = false
    }
  }

  private async finishJobWithoutPayment(job: DBComputeJob): Promise<void> {
    job.status = C2DStatusNumber.JobFinished
    job.statusText = C2DStatusText.JobFinished
    await this.db.updateJob(job)
  }

  private async calculateSettlementDecision(
    job: DBComputeJob,
    expired: boolean
  ): Promise<{ decision: 'charge' | 'release'; amount: number; reason: string }> {
    if (expired) return { decision: 'release', amount: 0, reason: 'lock_expired' }
    if (job.status !== C2DStatusNumber.JobSettle) {
      return decideSettlement(job, 0, this.privateDatasetPolicies.has(job.environment))
    }

    const env = await this.getComputeEnvironment(job.payment.chainId, job.environment)
    const fee = env?.fees?.[job.payment.chainId]?.find(
      (candidate) => candidate.feeToken === job.payment.token
    )
    const duration =
      Math.abs(parseFloat(job.algoStopTimestamp) - parseFloat(job.algoStartTimestamp)) +
      this.getValidBuildDurationSeconds(job)
    if (!env || !fee || !Number.isFinite(duration)) {
      return { decision: 'release', amount: 0, reason: 'settlement_configuration_error' }
    }

    let billableDuration = Math.min(duration, job.maxJobDuration)
    if (env.minJobDuration && billableDuration < env.minJobDuration) {
      billableDuration = env.minJobDuration
    }
    const cost = this.getTotalCostOfJob(job.resources, billableDuration, fee)
    if (!Number.isFinite(cost) || cost < 0) {
      return { decision: 'release', amount: 0, reason: 'settlement_cost_invalid' }
    }
    return decideSettlement(job, cost, this.privateDatasetPolicies.has(job.environment))
  }

  private async reconcileJobSettlement(
    job: DBComputeJob,
    locks: any[],
    currentTimestamp: bigint
  ): Promise<void> {
    const payment = job.payment!
    const escrowAddress = this.escrow.getEscrowContractAddressForChain(payment.chainId)
    if (!escrowAddress) {
      CORE_LOGGER.error(`No escrow address for settlement job ${job.jobId}`)
      return
    }
    const lock = locks.find(
      (candidate) => BigInt(candidate.jobId.toString()) === BigInt(job.jobIdHash)
    )
    const expired = Boolean(lock && currentTimestamp > BigInt(lock.expiry.toString()))
    const settlementKey = create256Hash(
      `${payment.chainId}:${escrowAddress.toLowerCase()}:${job.jobIdHash}`
    )
    let intent = await this.db.getSettlementByKey(settlementKey)
    const decision = intent
      ? {
          decision: intent.decision,
          amount: intent.amount,
          reason: intent.reason
        }
      : await this.calculateSettlementDecision(job, expired)
    let preparedBlock = intent?.preparedBlock
    if (!intent) {
      let preparedTransaction: {
        transactionHash: string
        rawTransaction: string
      } | null = null
      if (lock) {
        preparedBlock = await this.escrow.getCurrentBlockNumber(payment.chainId)
        const proof = JSON.stringify(omitDBComputeFieldsFromComputeJob(job))
        preparedTransaction = expired
          ? await this.escrow.prepareCancelExpiredLock(
              payment.chainId,
              job.jobId,
              payment.token,
              job.owner
            )
          : await this.escrow.prepareClaimLock(
              payment.chainId,
              job.jobId,
              payment.token,
              job.owner,
              decision.amount,
              proof
            )
        if (!preparedTransaction) {
          CORE_LOGGER.warn(`Could not prepare settlement for job ${job.jobId}`)
          return
        }
      } else {
        if (!payment.lockTx) {
          CORE_LOGGER.warn(`Missing lock transaction for settlement job ${job.jobId}`)
          return
        }
        const lockReceipt = await this.escrow.getSettlementTransactionReceipt(
          payment.chainId,
          payment.lockTx
        )
        if (!lockReceipt.confirmed || lockReceipt.blockNumber === undefined) {
          CORE_LOGGER.warn(`Cannot establish settlement event range for job ${job.jobId}`)
          return
        }
        preparedBlock = lockReceipt.blockNumber
      }
      const now = Date.now()
      const expected: DBSettlementIntent = {
        settlementKey,
        jobId: job.jobId,
        jobIdHash: job.jobIdHash,
        chainId: payment.chainId,
        escrowAddress,
        token: payment.token,
        payer: job.owner,
        decision: decision.decision,
        amount: decision.amount,
        reason: decision.reason,
        preparedBlock,
        status: 'prepared',
        transactionHash: preparedTransaction?.transactionHash,
        rawTransaction: preparedTransaction?.rawTransaction,
        createdAt: now,
        updatedAt: now
      }
      await this.db.insertSettlementIntent(expected)
      intent = await this.db.getSettlementByKey(settlementKey)
      if (!intent || !sameSettlementIntent(intent, expected)) {
        throw new Error(`Conflicting settlement intent for job ${job.jobId}`)
      }
    }

    if (
      ['charged', 'not_charged', 'refunded', 'refund_required'].includes(intent.status)
    ) {
      await this.finishJobFromSettlement(job, intent)
      return
    }

    if (intent.transactionHash) {
      const receipt = await this.escrow.getSettlementTransactionReceipt(
        intent.chainId,
        intent.transactionHash
      )
      if (receipt.confirmed) {
        if (!receipt.success) {
          await this.db.updateSettlementStatus(intent.settlementKey, 'refund_required')
          intent.status = 'refund_required'
          await this.finishJobFromSettlement(job, intent)
          return
        }
        if (!(await this.reconcileSettlementEvent(job, intent))) {
          await this.db.updateSettlementStatus(intent.settlementKey, 'refund_required')
          intent.status = 'refund_required'
          await this.finishJobFromSettlement(job, intent)
        }
        return
      }
    }

    if (!lock) {
      if (!(await this.reconcileSettlementEvent(job, intent))) {
        await this.db.updateSettlementStatus(intent.settlementKey, 'unknown')
      }
      return
    }

    if (
      intent.status === 'unknown' ||
      !intent.transactionHash ||
      !intent.rawTransaction
    ) {
      await this.db.updateSettlementStatus(intent.settlementKey, 'unknown')
      return
    }
    const transactionHash = await this.escrow.broadcastSettlementTransaction(
      payment.chainId,
      intent.rawTransaction,
      intent.transactionHash
    )
    await this.db.updateSettlementStatus(
      intent.settlementKey,
      'broadcast',
      transactionHash
    )
    CORE_LOGGER.info(`Broadcast settlement for job ${job.jobId}: ${transactionHash}`)
  }

  private async reconcileSettlementEvent(
    job: DBComputeJob,
    intent: DBSettlementIntent
  ): Promise<boolean> {
    const event = await this.escrow.findSettlementEvent(
      intent.chainId,
      intent.preparedBlock,
      intent.jobIdHash,
      intent.token,
      intent.payer,
      this.getKeyManager().getEthAddress()
    )
    if (!event) return false

    let status: DBSettlementStatus
    if (event.mutation === 'cancel') {
      status = 'refunded'
    } else if (event.decision === 'release' && intent.decision === 'release') {
      status = 'not_charged'
    } else if (
      intent.decision !== 'charge' ||
      Math.abs(event.amount - intent.amount) > 1e-12
    ) {
      status = 'refund_required'
    } else {
      status = 'charged'
    }
    await this.db.updateSettlementStatus(
      intent.settlementKey,
      status,
      event.transactionHash,
      event.blockNumber,
      event.amount
    )
    intent.status = status
    intent.transactionHash = event.transactionHash
    intent.receiptBlock = event.blockNumber
    if (job.payment) {
      if (event.mutation === 'cancel') job.payment.cancelTx = event.transactionHash
      else job.payment.claimTx = event.transactionHash
      job.payment.cost = event.decision === 'charge' ? event.amount : 0
    }
    await this.finishJobFromSettlement(job, intent)
    return true
  }

  private async finishJobFromSettlement(
    job: DBComputeJob,
    intent: DBSettlementIntent
  ): Promise<void> {
    if (job.payment) {
      if (intent.status === 'charged') job.payment.cost = intent.amount
      else if (intent.status !== 'refund_required') job.payment.cost = 0
      if (
        intent.status !== 'refund_required' &&
        intent.transactionHash &&
        !job.payment.claimTx &&
        !job.payment.cancelTx
      ) {
        if (intent.status === 'refunded') {
          job.payment.cancelTx = intent.transactionHash
        } else {
          job.payment.claimTx = intent.transactionHash
        }
      }
    }
    job.status = C2DStatusNumber.JobFinished
    job.statusText = C2DStatusText.JobFinished
    await this.db.updateJob(job)
  }

  private async cleanUpUnknownLocks(
    chain: string,
    currentTimestamp: bigint,
    knownJobHashes: Set<string> = new Set()
  ) {
    try {
      const nodeAddress = this.getKeyManager().getEthAddress()
      const jobIds: any[] = []
      const tokens: string[] = []
      const payer: string[] = []

      const balocks = await this.escrow.getLocks(
        parseInt(chain),
        '0x0000000000000000000000000000000000000000',
        '0x0000000000000000000000000000000000000000',
        nodeAddress
      )
      if (!balocks || balocks.length === 0) {
        CORE_LOGGER.warn(`Could not find any locks for chain ${chain}, skipping cleanup`)
        return
      }
      for (const lock of balocks) {
        if (knownJobHashes.has(BigInt(lock.jobId.toString()).toString())) continue
        const lockExpiry = BigInt(lock.expiry.toString())
        if (currentTimestamp > lockExpiry) {
          jobIds.push(lock.jobId.toString())
          tokens.push(lock.token)
          payer.push(lock.payer)
        }
      }
      if (jobIds.length > 0) {
        try {
          const tx = await this.escrow.cancelExpiredLocks(
            parseInt(chain),
            jobIds,
            tokens,
            payer,
            false
          )
          CORE_LOGGER.warn(` Canceled locks on chain ${chain}, tx:${tx}`)
        } catch (e) {
          // not critical, since we will try to cancel them at next run
          CORE_LOGGER.warn(`Tried to cancel some locks, errored: ${e.message}`)
        }
      }
    } catch (e) {
      CORE_LOGGER.error(`Error during cleanup of unknown locks: ${e.message}`)
    }
  }

  private async cleanupOldImages(): Promise<void> {
    if (!this.docker) return

    try {
      const oldImages = await this.db.getOldImages(this.retentionDays)
      if (oldImages.length === 0) {
        CORE_LOGGER.debug('No old images to clean up')
        return
      }

      CORE_LOGGER.info(`Starting cleanup of ${oldImages.length} old Docker images`)
      let cleaned = 0
      let failed = 0

      for (const image of oldImages) {
        try {
          const dockerImage = this.docker.getImage(image)
          await dockerImage.remove({ force: true })
          await this.db.deleteImage(image)
          cleaned++
          CORE_LOGGER.info(`Successfully removed old image: ${image}`)
        } catch (e) {
          failed++
          // Image might be in use or already deleted - log but don't throw
          CORE_LOGGER.debug(`Could not remove image ${image}: ${e.message}`)
        }
      }

      CORE_LOGGER.info(
        `Image cleanup completed: ${cleaned} removed, ${failed} failed (may be in use)`
      )
    } catch (e) {
      CORE_LOGGER.error(`Error during image cleanup: ${e.message}`)
    }
  }

  // eslint-disable-next-line require-await
  public override async getComputeEnvironments(
    chainId?: number
  ): Promise<ComputeEnvironment[]> {
    /**
     * Returns all cluster's compute environments, filtered by a specific chainId if needed. Env's id already contains the cluster hash
     */
    if (!this.docker) return []
    const filteredEnvs = []
    // const systemInfo = this.docker ? await this.docker.info() : null
    for (const env of this.envs) {
      if (!chainId || (env.fees && Object.hasOwn(env.fees, String(chainId)))) {
        const computeEnv = JSON.parse(JSON.stringify(env))

        // TO DO - At some point in time we need to handle multiple runtimes
        // console.log('********************************')
        // console.log(systemInfo.GenericResources)
        // console.log('********************************')
        // if (systemInfo.Runtimes) computeEnv.runtimes = systemInfo.Runtimes
        // if (systemInfo.DefaultRuntime)
        // computeEnv.defaultRuntime = systemInfo.DefaultRuntime
        const {
          totalJobs,
          totalFreeJobs,
          usedResources,
          usedFreeResources,
          queuedJobs,
          queuedFreeJobs,
          maxWaitTime,
          maxWaitTimeFree,
          maxRunningTime,
          maxRunningTimeFree
        } = await this.getUsedResources(computeEnv)
        computeEnv.runningJobs = totalJobs
        computeEnv.runningfreeJobs = totalFreeJobs
        computeEnv.queuedJobs = queuedJobs
        computeEnv.queuedFreeJobs = queuedFreeJobs
        computeEnv.queMaxWaitTime = maxWaitTime
        computeEnv.queMaxWaitTimeFree = maxWaitTimeFree
        computeEnv.runMaxWaitTime = maxRunningTime
        computeEnv.runMaxWaitTimeFree = maxRunningTimeFree
        if (computeEnv.resources) {
          for (let i = 0; i < computeEnv.resources.length; i++) {
            if (computeEnv.resources[i].id in usedResources)
              computeEnv.resources[i].inUse = usedResources[computeEnv.resources[i].id]
            else computeEnv.resources[i].inUse = 0
          }
        }
        if (computeEnv.free && computeEnv.free.resources) {
          for (let i = 0; i < computeEnv.free.resources.length; i++) {
            if (computeEnv.free.resources[i].id in usedFreeResources)
              computeEnv.free.resources[i].inUse =
                usedFreeResources[computeEnv.free.resources[i].id]
            else computeEnv.free.resources[i].inUse = 0
          }
        }
        filteredEnvs.push(computeEnv)
      }
    }

    return filteredEnvs
  }

  private parseImage(image: string) {
    let registry = C2DEngineDocker.DEFAULT_DOCKER_REGISTRY
    let name = image
    let ref = 'latest'

    const atIdx = name.indexOf('@')
    const colonIdx = name.lastIndexOf(':')

    if (atIdx !== -1) {
      ref = name.slice(atIdx + 1)
      name = name.slice(0, atIdx)
    } else if (colonIdx !== -1 && !name.slice(colonIdx).includes('/')) {
      ref = name.slice(colonIdx + 1)
      name = name.slice(0, colonIdx)
    }

    const firstSlash = name.indexOf('/')
    if (firstSlash !== -1) {
      const potential = name.slice(0, firstSlash)
      if (potential.includes('.') || potential.includes(':')) {
        registry = potential.includes('localhost')
          ? `http://${potential}`
          : `https://${potential}`
        name = name.slice(firstSlash + 1)
      }
    }

    if (registry === C2DEngineDocker.DEFAULT_DOCKER_REGISTRY && !name.includes('/')) {
      name = `library/${name}`
    }

    return { registry, name, ref }
  }

  public async getDockerManifest(
    image: string,
    encryptedDockerRegistryAuth?: string
  ): Promise<any> {
    const { registry, name, ref } = this.parseImage(image)
    const url = `${registry}/v2/${name}/manifests/${ref}`

    // Use user provided registry auth or get it from the config
    let dockerRegistryAuth: dockerRegistryAuth | null = null
    if (encryptedDockerRegistryAuth) {
      const decryptedDockerRegistryAuth = await this.keyManager.decrypt(
        Uint8Array.from(Buffer.from(encryptedDockerRegistryAuth, 'hex')),
        EncryptMethod.ECIES
      )
      dockerRegistryAuth = JSON.parse(decryptedDockerRegistryAuth.toString())
    } else {
      dockerRegistryAuth = this.getDockerRegistryAuth(registry)
    }

    let headers: Record<string, string> = {
      Accept:
        'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json'
    }

    // If we have auth credentials, add Basic auth header to initial request
    if (dockerRegistryAuth) {
      // Use auth string if available, otherwise encode username:password
      const authString = dockerRegistryAuth.auth
        ? dockerRegistryAuth.auth
        : Buffer.from(
            `${dockerRegistryAuth.username}:${dockerRegistryAuth.password}`
          ).toString('base64')
      headers.Authorization = `Basic ${authString}`
      CORE_LOGGER.debug(
        `Using docker registry auth for ${registry} to get manifest for image ${image}`
      )
    }

    let response = await fetch(url, { headers })

    if (response.status === 401) {
      const match = (response.headers.get('www-authenticate') || '').match(
        /Bearer realm="([^"]+)",service="([^"]+)"/
      )
      if (match) {
        const tokenUrl = new URL(match[1])
        tokenUrl.searchParams.set('service', match[2])
        tokenUrl.searchParams.set('scope', `repository:${name}:pull`)

        // Add Basic auth to token request if we have credentials
        const tokenHeaders: Record<string, string> = {}
        if (dockerRegistryAuth) {
          // Use auth string if available, otherwise encode username:password
          const authString = dockerRegistryAuth.auth
            ? dockerRegistryAuth.auth
            : Buffer.from(
                `${dockerRegistryAuth.username}:${dockerRegistryAuth.password}`
              ).toString('base64')
          tokenHeaders.Authorization = `Basic ${authString}`
        }

        const { token } = (await fetch(tokenUrl.toString(), {
          headers: tokenHeaders
        }).then((r) => r.json())) as {
          token: string
        }
        headers = { ...headers, Authorization: `Bearer ${token}` }
        response = await fetch(url, { headers })
      }
    }

    if (!response.ok) {
      const body = await response.text()
      throw new Error(
        `Failed to get manifest: ${response.status} ${response.statusText} - ${body}`
      )
    }
    return await response.json()
  }

  /**
   * Checks the docker image by looking at local images first, then remote manifest
   * @param image name or tag
   * @param encryptedDockerRegistryAuth optional encrypted auth for remote registry
   * @param platform optional platform to validate against
   * @returns ValidateParams with valid flag and platform validation result
   */
  public async checkDockerImage(
    image: string,
    encryptedDockerRegistryAuth?: string,
    platform?: RunningPlatform
  ): Promise<ValidateParams> {
    // Step 1: Try to check local image first
    if (this.docker) {
      try {
        const dockerImage = this.docker.getImage(image)
        const imageInfo = await dockerImage.inspect()

        // Extract platform information from local image
        const localPlatform = {
          architecture: imageInfo.Architecture || 'amd64',
          os: imageInfo.Os || 'linux'
        }

        // Normalize architecture (amd64 -> x86_64 for compatibility)
        if (localPlatform.architecture === 'amd64') {
          localPlatform.architecture = 'x86_64'
        }

        // Validate platform if required
        const isValidPlatform = platform
          ? checkManifestPlatform(localPlatform, platform)
          : true

        if (isValidPlatform) {
          CORE_LOGGER.debug(`Image ${image} found locally and platform is valid`)
          return { valid: true }
        } else {
          CORE_LOGGER.warn(
            `Image ${image} found locally but platform mismatch: ` +
              `local=${localPlatform.architecture}/${localPlatform.os}, ` +
              `required=${platform.architecture}/${platform.os}`
          )
          return {
            valid: false,
            status: 400,
            reason:
              `Platform mismatch: image is ${localPlatform.architecture}/${localPlatform.os}, ` +
              `but environment requires ${platform.architecture}/${platform.os}`
          }
        }
      } catch (localErr: any) {
        // Image not found locally or error inspecting - fall through to remote check
        CORE_LOGGER.debug(
          `Image ${image} not found locally (${localErr.message}), checking remote registry`
        )
      }
    }

    // Step 2: Fall back to remote registry check (existing behavior)
    try {
      const manifest = await this.getDockerManifest(image, encryptedDockerRegistryAuth)

      const platforms = Array.isArray(manifest.manifests)
        ? manifest.manifests.map((entry: any) => entry.platform)
        : [manifest.platform]

      const isValidPlatform = platforms.some((entry: any) =>
        checkManifestPlatform(entry, platform)
      )

      return { valid: isValidPlatform }
    } catch (err: any) {
      CORE_LOGGER.error(`Unable to get Manifest for image ${image}: ${err.message}`)
      if (err.errors?.length) CORE_LOGGER.error(JSON.stringify(err.errors))

      return {
        valid: false,
        status: 404,
        reason: err.errors?.length ? JSON.stringify(err.errors) : err.message
      }
    }
  }

  // eslint-disable-next-line require-await
  public override async startComputeJob(
    assets: ComputeAsset[],
    algorithm: ComputeAlgorithm,
    output: string,
    environment: string,
    owner: string,
    maxJobDuration: number,
    resources: ComputeResourceRequest[],
    payment: DBComputeJobPayment,
    jobId: string,
    metadata?: DBComputeJobMetadata,
    additionalViewers?: string[],
    queueMaxWaitTime?: number,
    encryptedDockerRegistryAuth?: string
  ): Promise<ComputeJob[]> {
    if (!this.docker) return []
    // TO DO - iterate over resources and get default runtime
    const isFree: boolean = !(payment && payment.lockTx)

    if (metadata && Object.keys(metadata).length > 0) {
      const metadataSize = JSON.stringify(metadata).length
      if (metadataSize > 1024) {
        throw new Error('Metadata size is too large')
      }
    }

    const envIdWithHash = environment && environment.indexOf('-') > -1
    const env = await this.getComputeEnvironment(
      payment && payment.chainId ? payment.chainId : null,
      envIdWithHash ? environment : null,
      environment
    )
    if (!env) {
      throw new Error(`Invalid environment ${environment}`)
    }
    // C2D - Check image, check arhitecture, etc
    const image = getAlgorithmImage(algorithm, jobId)
    // ex: node@sha256:1155995dda741e93afe4b1c6ced2d01734a6ec69865cc0997daf1f4db7259a36
    if (!image) {
      // send a 500 with the error message
      throw new Error(
        `Unable to extract docker image ${image} from algoritm: ${JSON.stringify(
          algorithm
        )}`
      )
    }
    const privateDatasetPolicy = this.privateDatasetPolicies.get(env.id)
    if (privateDatasetPolicy) {
      assertPrivateDatasetJob(privateDatasetPolicy, image, assets.length)
    }
    let additionalDockerFiles: { [key: string]: any } = null
    if (
      algorithm.meta &&
      algorithm.meta.container &&
      algorithm.meta.container.additionalDockerFiles
    ) {
      additionalDockerFiles = JSON.parse(
        JSON.stringify(algorithm.meta.container.additionalDockerFiles)
      )
      // make sure that we don't keep them in the db structure
      algorithm.meta.container.additionalDockerFiles = null
      if (queueMaxWaitTime && queueMaxWaitTime > 0) {
        throw new Error(`additionalDockerFiles cannot be used with queued jobs`)
      }
    }
    if (
      isFree &&
      algorithm.meta.container &&
      algorithm.meta.container.dockerfile &&
      !env.free?.allowImageBuild
    ) {
      throw new Error(`Building image is not allowed for free jobs`)
    }

    const job: DBComputeJob = {
      clusterHash: this.getC2DConfig().hash,
      containerImage: image,
      owner,
      jobId,
      jobIdHash: create256Hash(jobId),
      dateCreated: String(Date.now() / 1000),
      dateFinished: null,
      status:
        queueMaxWaitTime && queueMaxWaitTime > 0
          ? C2DStatusNumber.JobQueued
          : C2DStatusNumber.JobStarted,
      statusText:
        queueMaxWaitTime && queueMaxWaitTime > 0
          ? C2DStatusText.JobQueued
          : C2DStatusText.JobStarted,
      results: [],
      algorithm,
      assets,
      maxJobDuration,
      environment,
      configlogURL: null,
      publishlogURL: null,
      algologURL: null,
      outputsURL: null,
      stopRequested: false,
      isRunning: true,
      isStarted: false,
      resources,
      isFree,
      algoStartTimestamp: '0',
      algoStopTimestamp: '0',
      payment,
      metadata,
      additionalViewers,
      terminationDetails: { exitCode: null, OOMKilled: null },
      algoDuration: 0,
      queueMaxWaitTime: queueMaxWaitTime || 0,
      encryptedDockerRegistryAuth, // we store the encrypted docker registry auth in the job
      output,
      buildStartTimestamp: '0',
      buildStopTimestamp: '0'
    }

    if (algorithm.meta.container && algorithm.meta.container.dockerfile) {
      // we need to build the image if job is not queued
      if (queueMaxWaitTime === 0) {
        job.status = C2DStatusNumber.BuildImage
        job.statusText = C2DStatusText.BuildImage
      }
    } else {
      // already built, we need to validate it
      const validation = await this.checkDockerImage(
        image,
        job.encryptedDockerRegistryAuth,
        env.platform
      )
      if (!validation.valid)
        throw new Error(
          `Cannot find image ${image} for ${env.platform.architecture}. Maybe it does not exist or it's build for other arhitectures.`
        )
      if (queueMaxWaitTime === 0) {
        job.status = C2DStatusNumber.PullImage
        job.statusText = C2DStatusText.PullImage
      }
    }

    if (!this.makeJobFolders(job)) {
      throw new Error('Storage failure')
    }
    // make sure we actually were able to insert on DB
    const addedId = await this.db.newJob(job)
    if (!addedId) {
      return []
    }
    if (queueMaxWaitTime === 0) {
      if (algorithm.meta.container && algorithm.meta.container.dockerfile) {
        this.buildImage(job, additionalDockerFiles)
      } else {
        this.pullImage(job)
      }
    }
    // only now set the timer
    if (!this.cronTimer) {
      this.setNewTimer()
    }
    const cjob: ComputeJob = omitDBComputeFieldsFromComputeJob(job)
    // we add cluster hash to user output
    cjob.jobId = this.getC2DConfig().hash + '-' + cjob.jobId
    // cjob.jobId = jobId
    return [cjob]
  }

  // eslint-disable-next-line require-await
  public override async stopComputeJob(
    jobId: string,
    owner: string,
    agreementId?: string
  ): Promise<ComputeJob[]> {
    const jobs = await this.db.getJob(jobId, agreementId, owner)
    if (jobs.length === 0) {
      return []
    }
    const statusResults = []
    for (const job of jobs) {
      job.stopRequested = true
      await this.db.updateJob(job)
      const res: ComputeJob = omitDBComputeFieldsFromComputeJob(job)
      statusResults.push(res)
    }

    return statusResults
  }

  // eslint-disable-next-line require-await
  protected async getResults(jobId: string): Promise<ComputeResult[]> {
    const res: ComputeResult[] = []
    try {
      const jobs = await this.db.getJob(jobId)
      if (jobs.length !== 1 || jobs[0].output) return res
      const environment = await this.getJobEnvironment(jobs[0])
      const policy = environment?.consumerResultPolicy
      if (!policy) return res

      const filename = policy.mode === 'singleJson' ? 'result.json' : 'outputs.tar'
      const outputStat = statSync(
        this.getStoragePath() + '/' + jobId + '/data/outputs/' + filename
      )
      res.push({
        filename,
        filesize: outputStat.size,
        type: 'output',
        index: 0
      })
    } catch (e) {}
    return res
  }

  // eslint-disable-next-line require-await
  public override async getComputeJobStatus(
    consumerAddress?: string,
    agreementId?: string,
    jobId?: string
  ): Promise<ComputeJob[]> {
    const jobs = await this.db.getJob(jobId, agreementId, consumerAddress)
    if (jobs.length === 0) {
      return []
    }
    const statusResults = []
    for (const job of jobs) {
      const res: ComputeJob = omitDBComputeFieldsFromComputeJob(job)
      if (typeof this.db.getSettlementByJobId === 'function') {
        res.settlement = projectSettlement(await this.db.getSettlementByJobId(job.jobId))
      }
      // add results for algoLogs
      res.results = await this.getResults(job.jobId)
      statusResults.push(res)
    }

    return statusResults
  }

  // eslint-disable-next-line require-await
  public override async getComputeJobResult(
    consumerAddress: string,
    jobId: string,
    index: number,
    offset: number = 0
  ): Promise<{ stream: Readable; headers: any }> {
    const jobs = await this.db.getJob(jobId, null, null)
    if (jobs.length === 0 || jobs.length > 1) {
      throw new Error(`Cannot find job with id ${jobId}`)
    }
    const normalizedConsumer = consumerAddress.toLowerCase()
    if (
      jobs[0].owner.toLowerCase() !== normalizedConsumer &&
      (!jobs[0].additionalViewers ||
        !jobs[0].additionalViewers.some(
          (viewer) => viewer.toLowerCase() === normalizedConsumer
        ))
    ) {
      // consumerAddress is not the owner and not in additionalViewers
      throw new Error(
        `${consumerAddress} is not authorized to get results for job with id ${jobId}`
      )
    }
    const results = await this.getResults(jobId)
    for (const i of results) {
      if (i.index === index && i.type === 'output') {
        if (!Number.isSafeInteger(offset) || offset < 0 || offset >= i.filesize) {
          return null
        }
        const filePath =
          this.getStoragePath() + '/' + jobId + '/data/outputs/' + i.filename
        const contentType =
          i.filename === 'result.json'
            ? 'application/json; charset=utf-8'
            : 'application/octet-stream'
        return {
          stream: createReadStream(filePath, offset > 0 ? { start: offset } : undefined),
          headers: {
            'Content-Type': contentType,
            'Content-Length': String(Math.max(0, i.filesize - offset)),
            'Cache-Control': 'private, no-store',
            'X-Content-Type-Options': 'nosniff'
          }
        }
      }
    }
    return null
  }

  private setNewTimer() {
    if (this.cronTimer) {
      return
    }
    // don't set the cron if we don't have compute environments
    if (this.envs.length > 0)
      this.cronTimer = setTimeout(this.InternalLoop.bind(this), this.cronTime)
  }

  private async InternalLoop() {
    // this is the internal loop of docker engine
    // gets list of all running jobs and process them one by one

    // Prevent concurrent execution
    if (this.isInternalLoopRunning) {
      CORE_LOGGER.debug(
        `InternalLoop already running for engine ${this.getC2DConfig().hash}, skipping this execution`
      )
      return
    }

    this.isInternalLoopRunning = true

    if (this.cronTimer) {
      clearTimeout(this.cronTimer)
      this.cronTimer = null
    }
    try {
      // get all running jobs
      const jobs = await this.db.getRunningJobs(this.getC2DConfig().hash)

      if (jobs.length === 0) {
        CORE_LOGGER.debug('No C2D jobs found for engine ' + this.getC2DConfig().hash)
      } else {
        CORE_LOGGER.debug(
          `Got ${jobs.length} jobs for engine ${this.getC2DConfig().hash}`
        )
      }

      if (jobs.length > 0) {
        const promises: any = []
        for (const job of jobs) {
          promises.push(this.processJob(job))
        }
        // wait for all promises, there is no return
        await Promise.all(promises)
      }
    } catch (e) {
      CORE_LOGGER.error(`Error in C2D InternalLoop: ${e.message}`)
    } finally {
      // Reset the flag before setting the timer
      this.isInternalLoopRunning = false
      // set the cron again
      this.setNewTimer()
    }
  }

  private async createDockerContainer(
    containerInfo: ContainerCreateOptions,
    retry: boolean = false
  ): Promise<Dockerode.Container> | null {
    try {
      const container = await this.docker.createContainer(containerInfo)
      return container
    } catch (e) {
      CORE_LOGGER.error(`Unable to create docker container: ${e.message}`)
      if (
        e.message
          .toLowerCase()
          .includes('--storage-opt is supported only for overlay over xfs') &&
        retry
      ) {
        delete containerInfo.HostConfig.StorageOpt
        CORE_LOGGER.info('Retrying again without HostConfig.StorageOpt options...')
        // Retry without that option because it does not work
        return this.createDockerContainer(containerInfo)
      }
      return null
    }
  }

  private async inspectContainer(container: Dockerode.Container): Promise<any> {
    try {
      const data = await container.inspect()
      return data.State
    } catch (e) {
      CORE_LOGGER.error(`Unable to inspect docker container: ${e.message}`)
      return null
    }
  }

  private async createDockerVolume(
    volume: VolumeCreateOptions,
    retry: boolean = false
  ): Promise<boolean> {
    try {
      await this.docker.createVolume(volume)
      return true
    } catch (e) {
      CORE_LOGGER.error(`Unable to create docker volume: ${e.message}`)
      if (
        e.message.toLowerCase().includes('quota size requested but no quota support') &&
        retry
      ) {
        delete volume.DriverOpts
        CORE_LOGGER.info('Retrying again without DriverOpts options...')
        try {
          return this.createDockerVolume(volume)
        } catch (e) {
          CORE_LOGGER.error(
            `Unable to create docker volume without DriverOpts: ${e.message}`
          )
          return false
        }
      }
      return false
    }
  }

  private getImagePullTimeoutMs(): number {
    const raw = ENVIRONMENT_VARIABLES.C2D_DOWNLOAD_TIMEOUT.value
    const parsed = raw ? parseInt(raw, 10) : NaN
    if (Number.isFinite(parsed) && parsed > 0) {
      return parsed * 1000
    }
    return 15 * 60 * 1000
  }

  // eslint-disable-next-line require-await
  private async processJob(job: DBComputeJob) {
    CORE_LOGGER.info(
      `Process job ${job.jobId} started: [STATUS: ${job.status}: ${job.statusText}]`
    )

    // has to :
    //  - monitor running containers and stop them if over limits
    //  - monitor disc space and clean up
    /* steps:
       - wait until image is ready
       - create volume
       - after image is ready, create the container
       - download assets & algo into temp folder
       - download DDOS
       - tar and upload assets & algo to container
       - start the container
       - check if container is exceeding validUntil
       - if yes, stop it
       - download /data/outputs and store it locally (or upload it somewhere)
       - delete the container
       - delete the volume
       */

    if (
      job.status === C2DStatusNumber.BuildImage ||
      job.status === C2DStatusNumber.PullImage
    ) {
      // In-process build/pull: abort if stop was requested, then let the
      // existing catch handler finalize. Otherwise let it run.
      const activeBuildAbort = this.activeBuildAborts.get(job.jobId)
      if (activeBuildAbort) {
        if (job.stopRequested === true) {
          activeBuildAbort.abort()
        }
        return
      }

      // No active build abort → orphan (the process running build/pull died).
      const isBuild = job.status === C2DStatusNumber.BuildImage
      const nowSec = Date.now() / 1000
      job.status = isBuild
        ? C2DStatusNumber.BuildImageFailed
        : C2DStatusNumber.PullImageFailed
      job.statusText = isBuild
        ? C2DStatusText.BuildImageFailed
        : C2DStatusText.PullImageFailed
      job.isRunning = false
      if (isBuild) {
        job.buildStopTimestamp = String(nowSec)
      }
      job.dateFinished = String(nowSec)

      await this.db.updateJob(job)
      await this.cleanupJob(job)
      return
    }

    if (job.status === C2DStatusNumber.JobQueued) {
      // check if we can start the job now
      const now = String(Date.now() / 1000)
      if (job.queueMaxWaitTime < parseFloat(now) - parseFloat(job.dateCreated)) {
        job.status = C2DStatusNumber.JobQueuedExpired
        job.statusText = C2DStatusText.JobQueuedExpired
        job.isRunning = false
        job.dateFinished = now
        await this.db.updateJob(job)
        await this.cleanupJob(job)
        return
      }
      // check if resources are available now
      try {
        const chainId = job.payment && job.payment.chainId ? job.payment.chainId : null
        const allEnvs = await this.getComputeEnvironments(chainId)
        const env = allEnvs.find((e) => e.id === job.environment)
        if (!env) throw new Error(`Environment ${job.environment} not found`)
        await this.checkIfResourcesAreAvailable(job.resources, env, job.isFree, allEnvs)
      } catch (err) {
        // resources are still not available
        return
      }
      // resources are now available, let's start the job
      const { algorithm } = job
      if (algorithm?.meta.container && algorithm?.meta.container.dockerfile) {
        job.status = C2DStatusNumber.BuildImage
        job.statusText = C2DStatusText.BuildImage
        this.buildImage(job, null)
      } else {
        job.status = C2DStatusNumber.PullImage
        job.statusText = C2DStatusText.PullImage
        this.pullImage(job)
      }
      await this.db.updateJob(job)
    }

    if (job.status === C2DStatusNumber.ConfiguringVolumes) {
      // we have the image (etiher pulled or built)
      // if built, check if build process took all allocated time
      // if yes, stop the job
      const buildDuration = this.getValidBuildDurationSeconds(job)
      if (buildDuration > 0 && buildDuration >= job.maxJobDuration) {
        job.isStarted = false
        job.status = C2DStatusNumber.PublishingResults
        job.statusText = C2DStatusText.PublishingResults
        job.algoStartTimestamp = '0'
        job.algoStopTimestamp = '0'
        job.isRunning = false
        await this.db.updateJob(job)
        return
      }
      // now that we have the image ready, check it for vulnerabilities
      if (this.scanImages) {
        const imageLogFile =
          this.getStoragePath() + '/' + job.jobId + '/data/logs/image.log'
        try {
          const check = await this.checkImageVulnerability(job.containerImage)
          const logText =
            `Image scanned for vulnerabilities\nVulnerable:${check.vulnerable}\nSummary:` +
            JSON.stringify(check.summary, null, 2)
          CORE_LOGGER.debug(logText)
          appendFileSync(imageLogFile, logText)
          if (check.vulnerable) {
            job.status = C2DStatusNumber.VulnerableImage
            job.statusText = C2DStatusText.VulnerableImage
            job.isRunning = false
            job.dateFinished = String(Date.now() / 1000)
            await this.db.updateJob(job)
            await this.cleanupJob(job)
            return
          }
        } catch (error) {
          CORE_LOGGER.error(`Image scan failed for job ${job.jobId}: ${error.message}`)
          try {
            appendFileSync(imageLogFile, `Image scan failed: ${error.message}\n`)
          } catch (logError) {
            CORE_LOGGER.error(
              `Could not write image scan log for job ${job.jobId}: ${logError.message}`
            )
          }
          job.status = C2DStatusNumber.ImageScanFailed
          job.statusText = C2DStatusText.ImageScanFailed
          job.isRunning = false
          job.dateFinished = String(Date.now() / 1000)
          await this.db.updateJob(job)
          await this.cleanupJob(job)
          return
        }
      }
      // create the volume & create container
      // TO DO C2D:  Choose driver & size
      // get environment-specific resources for Docker device/hardware configuration
      const env = this.envs.find((e) => e.id === job.environment)
      const envResource = env?.resources || []
      const volume: VolumeCreateOptions = {
        Name: job.jobId + '-volume'
      }
      // volume
      /* const diskSize = this.getResourceRequest(job.resources, 'disk')
       if (diskSize && diskSize > 0) {
        volume.DriverOpts = {
          o: 'size=' + String(diskSize),
          device: 'local',
          type: 'local'
        }
      } */
      const volumeCreated = await this.createDockerVolume(volume, true)
      if (!volumeCreated) {
        job.status = C2DStatusNumber.VolumeCreationFailed
        job.statusText = C2DStatusText.VolumeCreationFailed
        job.isRunning = false
        job.dateFinished = String(Date.now() / 1000)
        await this.db.updateJob(job)
        await this.cleanupJob(job)
        return
      }

      // create the container
      const mountVols: any = { '/data': {} }
      const hostConfig: HostConfig = {
        // limit number of Pids container can spawn, to avoid flooding
        PidsLimit: 512,
        Mounts: [
          {
            Type: 'volume',
            Source: volume.Name,
            Target: '/data',
            ReadOnly: false
          }
        ]
      }
      if (!env.enableNetwork) {
        hostConfig.NetworkMode = 'none' // no network inside the container
      }
      // disk
      // if (diskSize && diskSize > 0) {
      //  hostConfig.StorageOpt = {
      //  size: String(diskSize)
      // }
      // }
      // ram
      const ramSize = this.getResourceRequest(job.resources, 'ram')
      if (ramSize && ramSize > 0) {
        hostConfig.Memory = ramSize * 1024 * 1024 * 1024 // config is in GB, docker wants bytes
        // set swap to same memory value means no swap (otherwise it use like 2X mem)
        hostConfig.MemorySwap = hostConfig.Memory
      }
      const cpus = this.getResourceRequest(job.resources, 'cpu')
      if (cpus && cpus > 0) {
        hostConfig.CpuPeriod = 100000 // 100 miliseconds is usually the default
        hostConfig.CpuQuota = Math.floor(cpus * hostConfig.CpuPeriod)
        // Pin the container to specific physical CPU cores
        const cpusetStr = this.allocateCpus(job.jobId, cpus, job.environment)
        if (cpusetStr) {
          hostConfig.CpusetCpus = cpusetStr
        }
      }
      const containerInfo: ContainerCreateOptions = {
        name: job.jobId + '-algoritm',
        Image: job.containerImage,
        AttachStdin: false,
        AttachStdout: true,
        AttachStderr: true,
        Tty: false,
        OpenStdin: false,
        StdinOnce: false,
        User: `${C2D_CONTAINER_UID}:${C2D_CONTAINER_GID}`,
        Volumes: mountVols,
        HostConfig: hostConfig
      }
      // TO DO - iterate over resources and get default runtime
      // TO DO - check resources and pass devices
      const dockerDeviceRequest = this.getDockerDeviceRequest(job.resources, envResource)
      if (dockerDeviceRequest) {
        containerInfo.HostConfig.DeviceRequests = dockerDeviceRequest
      }
      const advancedConfig = this.getDockerAdvancedConfig(job.resources, envResource)
      if (advancedConfig.Devices)
        containerInfo.HostConfig.Devices = advancedConfig.Devices
      if (advancedConfig.GroupAdd)
        containerInfo.HostConfig.GroupAdd = advancedConfig.GroupAdd
      containerInfo.HostConfig.SecurityOpt = [
        'no-new-privileges',
        ...(advancedConfig.SecurityOpt ?? [])
      ]
      if (advancedConfig.Binds) containerInfo.HostConfig.Binds = advancedConfig.Binds
      containerInfo.HostConfig.CapDrop = ['ALL']
      for (const cap of advancedConfig.CapDrop ?? []) {
        containerInfo.HostConfig.CapDrop.push(cap)
      }
      if (advancedConfig.CapAdd) containerInfo.HostConfig.CapAdd = advancedConfig.CapAdd
      if (advancedConfig.IpcMode)
        containerInfo.HostConfig.IpcMode = advancedConfig.IpcMode
      if (advancedConfig.ShmSize)
        containerInfo.HostConfig.ShmSize = advancedConfig.ShmSize
      if (job.algorithm?.meta.container.entrypoint) {
        const newEntrypoint = job.algorithm.meta.container.entrypoint.replace(
          '$ALGO',
          'data/transformations/algorithm'
        )
        containerInfo.Entrypoint = newEntrypoint.split(' ')
      }
      if (job.algorithm.envs) {
        const envVars: string[] = []
        for (const key of Object.keys(job.algorithm.envs)) {
          envVars.push(`${key}=${job.algorithm.envs[key]}`)
        }
        containerInfo.Env = envVars
      }
      // persistent Storage: bind-mount bucket files into the job container (localfs backend)
      for (const i in job.assets) {
        const asset = job.assets[i]
        if (!asset.fileObject || asset.fileObject.type !== 'nodePersistentStorage') {
          continue
        }
        const fo = asset.fileObject as { bucketId?: string; fileName?: string }
        if (!fo.bucketId || !fo.fileName) {
          CORE_LOGGER.error(
            `Job ${job.jobId} asset ${i}: nodePersistentStorage requires bucketId and fileName`
          )
          job.status = C2DStatusNumber.DataProvisioningFailed
          job.statusText = C2DStatusText.DataProvisioningFailed
          job.isRunning = false
          job.dateFinished = String(Date.now() / 1000)
          await this.db.updateJob(job)
          await this.cleanupJob(job)
          return
        }
        const ps = OceanNode.getInstance().getPersistentStorage()
        if (!ps) {
          CORE_LOGGER.error(
            `Job ${job.jobId} asset ${i}: persistent storage is not configured on this node`
          )
          job.status = C2DStatusNumber.DataProvisioningFailed
          job.statusText = C2DStatusText.DataProvisioningFailed
          job.isRunning = false
          job.dateFinished = String(Date.now() / 1000)
          await this.db.updateJob(job)
          await this.cleanupJob(job)
          return
        }
        try {
          const bindMount = await ps.getDockerMountObject(
            fo.bucketId,
            fo.fileName,
            job.owner
          )
          CORE_LOGGER.debug(
            `Mounting bucket ${fo.bucketId} to folder ${bindMount.Target}`
          )
          hostConfig.Mounts.push(bindMount)
          mountVols[bindMount.Target] = {}
        } catch (e) {
          const errMsg = e instanceof Error ? e.message : String(e)
          CORE_LOGGER.error(
            `Job ${job.jobId} asset ${i}: failed to resolve persistent storage bind: ${errMsg}`
          )
          job.status = C2DStatusNumber.DataProvisioningFailed
          job.statusText = C2DStatusText.DataProvisioningFailed
          job.isRunning = false
          job.dateFinished = String(Date.now() / 1000)
          await this.db.updateJob(job)
          await this.cleanupJob(job)
          return
        }
      }

      const container = await this.createDockerContainer(containerInfo, true)
      if (container) {
        job.status = C2DStatusNumber.Provisioning
        job.statusText = C2DStatusText.Provisioning
        await this.db.updateJob(job)
      } else {
        job.status = C2DStatusNumber.ContainerCreationFailed
        job.statusText = C2DStatusText.ContainerCreationFailed
        job.isRunning = false
        job.dateFinished = String(Date.now() / 1000)
        await this.db.updateJob(job)
        await this.cleanupJob(job)
        return
      }
      return
    }
    if (job.status === C2DStatusNumber.Provisioning) {
      // download algo & assets
      const ret = await this.uploadData(job)
      job.status = ret.status
      job.statusText = ret.statusText
      if (job.status !== C2DStatusNumber.RunningAlgorithm) {
        // failed, let's close it
        job.isRunning = false
        job.dateFinished = String(Date.now() / 1000)
        await this.db.updateJob(job)
        await this.cleanupJob(job)
      } else {
        await this.db.updateJob(job)
      }
    }
    if (job.status === C2DStatusNumber.RunningAlgorithm) {
      let container
      let details
      try {
        container = this.docker.getContainer(job.jobId + '-algoritm')
        details = await container.inspect()
      } catch (e) {
        console.error(
          'Could not retrieve container: ' +
            e.message +
            '\nBack to configuring volumes to create the container...'
        )
        job.isStarted = false
        job.status = C2DStatusNumber.ConfiguringVolumes
        job.statusText = C2DStatusText.ConfiguringVolumes
        job.isRunning = false
        await this.db.updateJob(job)
        return
      }

      if (job.isStarted === false) {
        // make sure is not started
        if (details && details.State.Running === false) {
          try {
            await container.start()
            job.isStarted = true
            job.algoStartTimestamp = String(Date.now() / 1000)
            await this.db.updateJob(job)
            CORE_LOGGER.info(`Container started successfully for job ${job.jobId}`)

            await this.measureContainerBaseSize(job, container)
            return
          } catch (e) {
            // container failed to start
            job.algoStartTimestamp = String(Date.now() / 1000)
            job.algoStopTimestamp = String(Date.now() / 1000)
            try {
              const algoLogFile =
                this.getStoragePath() + '/' + job.jobId + '/data/logs/algorithm.log'
              writeFileSync(algoLogFile, String(e.message))
            } catch (e) {
              CORE_LOGGER.error('Failed to write algorithm log file: ' + e.message)
            }
            CORE_LOGGER.error('Could not start container: ' + e.message)
            job.status = C2DStatusNumber.AlgorithmFailed
            job.statusText = C2DStatusText.AlgorithmFailed

            job.isRunning = false
            job.dateFinished = String(Date.now() / 1000)
            await this.db.updateJob(job)
            await this.cleanupJob(job)
            return
          }
        }
      } else {
        const canContinue = await this.monitorDiskUsage(job)
        if (!canContinue) {
          // Job was terminated due to disk quota exceeded
          return
        }

        const timeNow = Date.now() / 1000
        let expiry

        const buildDuration = this.getValidBuildDurationSeconds(job)
        if (buildDuration > 0) {
          // if job has build time, reduce the remaining algorithm runtime budget
          expiry = parseFloat(job.algoStartTimestamp) + job.maxJobDuration - buildDuration
        } else expiry = parseFloat(job.algoStartTimestamp) + job.maxJobDuration
        CORE_LOGGER.debug(
          'container running since timeNow: ' + timeNow + ' , Expiry: ' + expiry
        )
        if (timeNow > expiry || job.stopRequested) {
          // we need to stop the container
          // make sure is running
          if (details.State.Running === true) {
            try {
              await container.stop()
            } catch (e) {
              // we should never reach this, unless the container is already stopped or deleted by someone else
              CORE_LOGGER.debug('Could not stop container: ' + e.message)
            }
          }
          job.isStarted = false
          job.status = C2DStatusNumber.PublishingResults
          job.statusText = C2DStatusText.PublishingResults
          job.algoStopTimestamp = String(Date.now() / 1000)
          job.isRunning = false
          await this.db.updateJob(job)
          return
        } else {
          if (details.State.Running === false) {
            job.isStarted = false
            job.status = C2DStatusNumber.PublishingResults
            job.statusText = C2DStatusText.PublishingResults
            const containerFinishedAt =
              new Date(details.State.FinishedAt).getTime() / 1000
            job.algoStopTimestamp = String(
              containerFinishedAt > parseFloat(job.algoStartTimestamp)
                ? containerFinishedAt
                : Date.now() / 1000
            )
            job.isRunning = false
            await this.db.updateJob(job)
            return
          }
        }
      }
    }
    if (job.status === C2DStatusNumber.PublishingResults) {
      // get output
      job.status = C2DStatusNumber.JobSettle
      job.statusText = C2DStatusText.JobSettle
      let container
      try {
        container = this.docker.getContainer(job.jobId + '-algoritm')
      } catch (e) {
        CORE_LOGGER.debug('Could not retrieve container: ' + e.message)
        job.isRunning = false
        job.dateFinished = String(Date.now() / 1000)
        try {
          const algoLogFile =
            this.getStoragePath() + '/' + job.jobId + '/data/logs/algorithm.log'
          writeFileSync(algoLogFile, String(e.message))
        } catch (e) {
          CORE_LOGGER.error('Failed to write algorithm log file: ' + e.message)
        }
        await this.db.updateJob(job)
        await this.cleanupJob(job)
        return
      }
      const state = await this.inspectContainer(container)
      if (state) {
        job.terminationDetails.OOMKilled = state.OOMKilled
        job.terminationDetails.exitCode = state.ExitCode
      } else {
        job.terminationDetails.OOMKilled = null
        job.terminationDetails.exitCode = null
      }
      const environment = await this.getJobEnvironment(job)
      const resultPolicy: ConsumerResultPolicy = environment?.consumerResultPolicy
      let singleJsonResult: Buffer = null

      if (!container || !resultPolicy) {
        CORE_LOGGER.error(`Missing result policy or container for job ${job.jobId}`)
        job.status = C2DStatusNumber.ResultsFetchFailed
        job.statusText = C2DStatusText.ResultsFetchFailed
      } else if (resultPolicy.mode === 'singleJson') {
        try {
          singleJsonResult = await readSingleJsonResultArchive(
            (await container.getArchive({
              path: '/data/outputs/result.json'
            })) as unknown as Readable,
            resultPolicy.maxBytes
          )
          job.resultValidation = validateConsumerResultContract(
            singleJsonResult,
            resultPolicy
          )
        } catch (e) {
          CORE_LOGGER.error('Failed to validate result.json: ' + e.message)
          job.status = C2DStatusNumber.ResultsFetchFailed
          job.statusText = C2DStatusText.ResultsFetchFailed
        }
      }

      if (
        resultPolicy &&
        job.status !== C2DStatusNumber.ResultsFetchFailed &&
        container
      ) {
        const outputsPath = this.getStoragePath() + '/' + job.jobId + '/data/outputs/'
        try {
          let output: ComputeOutput = null
          let storage: Storage = null
          if (job.output) {
            const decryptedOutput = await this.keyManager.decrypt(
              Uint8Array.from(Buffer.from(job.output, 'hex')),
              EncryptMethod.ECIES
            )
            output = JSON.parse(decryptedOutput.toString()) as ComputeOutput
            storage = Storage.getStorageClass(output.remoteStorage, this.getConfig())
          }

          const canUpload =
            storage?.hasUpload &&
            'upload' in storage &&
            typeof storage.upload === 'function'

          if (resultPolicy.mode === 'singleJson') {
            if (canUpload) {
              let uploadStream = Readable.from([singleJsonResult])
              if (output.encryption?.key) {
                const key = Uint8Array.from(Buffer.from(output.encryption.key, 'hex'))
                uploadStream = this.keyManager.encryptStream(
                  uploadStream,
                  output.encryption.encryptMethod,
                  key
                ) as Readable
              }
              const filename =
                'result-' +
                this.getC2DConfig().hash +
                '-' +
                job.jobId +
                (output.encryption?.key ? '.json.enc' : '.json')
              await (
                storage as unknown as {
                  upload: (name: string, stream: Readable) => Promise<unknown>
                }
              ).upload(filename, uploadStream)
            } else {
              const resultPath = outputsPath + 'result.json'
              const temporaryResultPath = resultPath + '.tmp'
              try {
                writeFileSync(temporaryResultPath, singleJsonResult, { mode: 0o600 })
                renameSync(temporaryResultPath, resultPath)
              } finally {
                rmSync(temporaryResultPath, { force: true })
              }
            }
          } else {
            const archiveStream = (await container.getArchive({
              path: '/data/outputs'
            })) as unknown as Readable
            if (canUpload) {
              let uploadStream = archiveStream
              if (output.encryption?.key) {
                const key = Uint8Array.from(Buffer.from(output.encryption.key, 'hex'))
                uploadStream = this.keyManager.encryptStream(
                  uploadStream,
                  output.encryption.encryptMethod,
                  key
                ) as Readable
              }
              const filename =
                'outputs-' + this.getC2DConfig().hash + '-' + job.jobId + '.tar'
              await (
                storage as unknown as {
                  upload: (name: string, stream: Readable) => Promise<unknown>
                }
              ).upload(filename, uploadStream)
            } else {
              await pipeline(
                archiveStream,
                createWriteStream(outputsPath + 'outputs.tar')
              )
            }
          }
        } catch (e) {
          CORE_LOGGER.error('Failed to publish compute result: ' + e.message)
          job.status = C2DStatusNumber.ResultsUploadFailed
          job.statusText = C2DStatusText.ResultsUploadFailed
        }
      }
      job.isRunning = false
      job.dateFinished = String(Date.now() / 1000)
      await this.db.updateJob(job)
      await this.cleanupJob(job)
    }
  }

  // eslint-disable-next-line require-await
  private parseCpusetString(cpuset: string): number[] {
    const cores: number[] = []
    if (!cpuset) return cores
    for (const part of cpuset.split(',')) {
      if (part.includes('-')) {
        const [start, end] = part.split('-').map(Number)
        for (let i = start; i <= end; i++) {
          cores.push(i)
        }
      } else {
        cores.push(Number(part))
      }
    }
    return cores
  }

  private allocateCpus(jobId: string, count: number, envId: string): string | null {
    const envCores = this.envCpuCoresMap.get(envId)
    if (!envCores || envCores.length === 0 || count <= 0) return null
    const existing = this.cpuAllocations.get(jobId)
    if (existing && existing.length > 0) {
      const cpusetStr = existing.join(',')
      CORE_LOGGER.info(
        `CPU affinity: reusing existing cores [${cpusetStr}] for job ${jobId}`
      )
      return cpusetStr
    }

    const usedCores = new Set<number>()
    for (const cores of this.cpuAllocations.values()) {
      for (const core of cores) {
        usedCores.add(core)
      }
    }

    const freeCores: number[] = []
    for (const core of envCores) {
      if (!usedCores.has(core)) {
        freeCores.push(core)
        if (freeCores.length === count) break
      }
    }

    if (freeCores.length < count) {
      CORE_LOGGER.warn(
        `CPU affinity: not enough free cores for job ${jobId} in env ${envId} (requested=${count}, available=${freeCores.length}/${envCores.length})`
      )
      return null
    }

    this.cpuAllocations.set(jobId, freeCores)
    const cpusetStr = freeCores.join(',')
    CORE_LOGGER.info(`CPU affinity: allocated cores [${cpusetStr}] to job ${jobId}`)
    return cpusetStr
  }

  private releaseCpus(jobId: string): void {
    const cores = this.cpuAllocations.get(jobId)
    if (cores) {
      CORE_LOGGER.info(
        `CPU affinity: released cores [${cores.join(',')}] from job ${jobId}`
      )
      this.cpuAllocations.delete(jobId)
    }
  }

  /**
   * On startup, inspects running Docker containers to rebuild the CPU allocation map.
   */
  private async rebuildCpuAllocations(): Promise<void> {
    if (this.envCpuCoresMap.size === 0) return
    try {
      const jobs = await this.db.getRunningJobs(this.getC2DConfig().hash)
      for (const job of jobs) {
        try {
          const container = this.docker.getContainer(job.jobId + '-algoritm')
          const info = await container.inspect()
          const cpuset = info.HostConfig?.CpusetCpus
          if (cpuset) {
            const cores = this.parseCpusetString(cpuset)
            if (cores.length > 0) {
              this.cpuAllocations.set(job.jobId, cores)
              CORE_LOGGER.info(
                `CPU affinity: recovered allocation [${cpuset}] for running job ${job.jobId}`
              )
            }
          }
        } catch (e) {
          // Container may not exist yet (e.g., job is in pull/build phase)
        }
      }
    } catch (e) {
      CORE_LOGGER.error(`CPU affinity: failed to rebuild allocations: ${e.message}`)
    }
  }

  private async cleanupJob(job: DBComputeJob) {
    // cleaning up
    // - claim payment or release lock
    //  - get algo logs
    //  - delete volume
    //  - delete container

    this.jobImageSizes.delete(job.jobId)
    this.releaseCpus(job.jobId)

    try {
      const container = this.docker.getContainer(job.jobId + '-algoritm')
      if (container) {
        if (job.status !== C2DStatusNumber.AlgorithmFailed) {
          writeFileSync(
            this.getStoragePath() + '/' + job.jobId + '/data/logs/algorithm.log',
            await container.logs({
              stdout: true,
              stderr: true,
              follow: false
            })
          )
        }
        await container.remove()
      }
    } catch (e) {
      // console.error('Container not found! ' + e.message)
    }
    try {
      const volume = this.docker.getVolume(job.jobId + '-volume')
      if (volume) {
        try {
          await volume.remove()
        } catch (e) {
          CORE_LOGGER.error('Failed to remove volume: ' + e.message)
        }
      }
    } catch (e) {
      CORE_LOGGER.error('Container volume not found! ' + e.message)
    }
    try {
      // remove folders
      rmSync(this.getStoragePath() + '/' + job.jobId + '/data/inputs', {
        recursive: true,
        force: true
      })
    } catch (e) {
      console.error(
        `Could not delete inputs from path ${this.getStoragePath()} for job ID ${
          job.jobId
        }! ` + e.message
      )
    }
    try {
      rmSync(this.getStoragePath() + '/' + job.jobId + '/data/transformations', {
        recursive: true,
        force: true
      })
    } catch (e) {
      console.error(
        `Could not delete algorithms from path ${this.getStoragePath()} for job ID ${job.jobId}! ` +
          e.message
      )
    }
  }

  private deleteOutputFolder(job: DBComputeJob) {
    rmSync(this.getStoragePath() + '/' + job.jobId + '/data/outputs/', {
      recursive: true,
      force: true
    })
  }

  private getDiskQuota(job: DBComputeJob): number {
    if (!job.resources) return 0

    const diskResource = job.resources.find((resource) => resource.id === 'disk')
    return diskResource ? diskResource.amount : 0
  }

  // Inspect the real runtime size of the container
  private async measureContainerBaseSize(
    job: DBComputeJob,
    container: Dockerode.Container
  ): Promise<void> {
    try {
      if (this.jobImageSizes.has(job.jobId)) {
        CORE_LOGGER.debug(`Using cached base size for job ${job.jobId.slice(-8)}`)
        return
      }

      // Wait for container filesystem to stabilize
      await new Promise((resolve) => setTimeout(resolve, 3000))

      const actualBaseSize = await this.getContainerDiskUsage(container.id, '/')
      this.jobImageSizes.set(job.jobId, actualBaseSize)

      CORE_LOGGER.info(
        `Base container ${job.containerImage} runtime size: ${(
          actualBaseSize /
          1024 /
          1024 /
          1024
        ).toFixed(2)}GB`
      )
    } catch (error) {
      CORE_LOGGER.error(`Failed to measure base container size: ${error.message}`)
      this.jobImageSizes.set(job.jobId, 0)
    }
  }

  private async getContainerDiskUsage(
    containerName: string,
    path: string = '/data'
  ): Promise<number> {
    try {
      const container = this.docker.getContainer(containerName)
      const containerInfo = await container.inspect()
      if (!containerInfo.State.Running) {
        CORE_LOGGER.debug(
          `Container ${containerName} is not running, cannot check disk usage`
        )
        return 0
      }

      const exec = await container.exec({
        Cmd: ['du', '-sb', path],
        AttachStdout: true,
        AttachStderr: true
      })

      const stream = await exec.start({ Detach: false, Tty: false })

      const chunks: Buffer[] = []
      for await (const chunk of stream) {
        chunks.push(chunk as Buffer)
      }

      const output = Buffer.concat(chunks).toString()

      const match = output.match(/(\d+)\s/)
      return match ? parseInt(match[1], 10) : 0
    } catch (error) {
      CORE_LOGGER.error(
        `Failed to get container disk usage for ${containerName}: ${error.message}`
      )
      return 0
    }
  }

  private async monitorDiskUsage(job: DBComputeJob): Promise<boolean> {
    const diskQuota = this.getDiskQuota(job)
    if (diskQuota <= 0) return true

    const containerName = job.jobId + '-algoritm'
    const totalUsage = await this.getContainerDiskUsage(containerName, '/')
    const baseImageSize = this.jobImageSizes.get(job.jobId) || 0
    const algorithmUsage = Math.max(0, totalUsage - baseImageSize)

    const usageGB = (algorithmUsage / 1024 / 1024 / 1024).toFixed(2)
    const quotaGB = diskQuota.toFixed(1)
    const usagePercent = (
      (algorithmUsage / 1024 / 1024 / 1024 / diskQuota) *
      100
    ).toFixed(1)

    CORE_LOGGER.info(
      `Job ${job.jobId.slice(-8)} disk: ${usageGB}GB / ${quotaGB}GB (${usagePercent}%)`
    )

    if (algorithmUsage / 1024 / 1024 / 1024 > diskQuota) {
      CORE_LOGGER.warn(
        `DISK QUOTA EXCEEDED - Stopping job ${job.jobId}: ${usageGB}GB used, ${quotaGB}GB allowed`
      )

      try {
        const container = this.docker.getContainer(containerName)
        await container.stop()
        CORE_LOGGER.info(`Container stopped for job ${job.jobId}`)
      } catch (e) {
        CORE_LOGGER.warn(`Could not stop container: ${e.message}`)
      }

      job.status = C2DStatusNumber.DiskQuotaExceeded
      job.statusText = C2DStatusText.DiskQuotaExceeded
      job.isRunning = false
      job.isStarted = false
      job.algoStopTimestamp = String(Date.now() / 1000)
      job.dateFinished = String(Date.now() / 1000)

      await this.db.updateJob(job)
      await this.cleanupJob(job)
      CORE_LOGGER.info(`Job ${job.jobId} terminated - DISK QUOTA EXCEEDED`)

      return false
    }

    return true
  }

  private async pullImage(originaljob: DBComputeJob) {
    const job = JSON.parse(JSON.stringify(originaljob)) as DBComputeJob
    const imageLogFile = this.getStoragePath() + '/' + job.jobId + '/data/logs/image.log'
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.getImagePullTimeoutMs())
    this.activeBuildAborts.set(job.jobId, controller)
    try {
      // Get registry auth for the image
      const { registry } = this.parseImage(job.containerImage)
      // Use user provided registry auth or get it from the config
      let dockerRegistryAuthForPull: any
      if (originaljob.encryptedDockerRegistryAuth) {
        const decryptedDockerRegistryAuth = await this.keyManager.decrypt(
          Uint8Array.from(Buffer.from(originaljob.encryptedDockerRegistryAuth, 'hex')),
          EncryptMethod.ECIES
        )
        dockerRegistryAuthForPull = JSON.parse(decryptedDockerRegistryAuth.toString())
      } else {
        dockerRegistryAuthForPull = this.getDockerRegistryAuth(registry)
      }

      // Prepare authconfig for Dockerode if credentials are available
      const pullOptions: any = {}
      if (dockerRegistryAuthForPull) {
        // Extract hostname from registry URL (remove protocol)
        const registryUrl = new URL(registry)
        const serveraddress =
          registryUrl.hostname + (registryUrl.port ? `:${registryUrl.port}` : '')

        // Use auth string if available, otherwise encode username:password
        const authString = dockerRegistryAuthForPull.auth
          ? dockerRegistryAuthForPull.auth
          : Buffer.from(
              `${dockerRegistryAuthForPull.username}:${dockerRegistryAuthForPull.password}`
            ).toString('base64')

        pullOptions.authconfig = {
          serveraddress,
          ...(dockerRegistryAuthForPull.auth
            ? { auth: authString }
            : {
                username: dockerRegistryAuthForPull.username,
                password: dockerRegistryAuthForPull.password
              })
        }
        CORE_LOGGER.debug(
          `Using docker registry auth for ${registry} to pull image ${job.containerImage}`
        )
      }
      pullOptions.abortSignal = controller.signal
      const pullStream = await this.docker.pull(job.containerImage, pullOptions)
      await new Promise((resolve, reject) => {
        let wroteStatusBanner = false
        this.docker.modem.followProgress(
          pullStream,
          (err: any, res: any) => {
            // onFinished
            if (err) {
              appendFileSync(imageLogFile, String(err.message))
              return reject(err)
            }
            const logText = `Successfully pulled image: ${job.containerImage}`
            CORE_LOGGER.debug(logText)
            appendFileSync(imageLogFile, logText + '\n')
            // Track image usage
            this.updateImageUsage(job.containerImage).catch((e) => {
              CORE_LOGGER.debug(`Failed to track image usage: ${e.message}`)
            })
            resolve(res)
          },
          (progress: any) => {
            // onProgress
            if (!wroteStatusBanner) {
              wroteStatusBanner = true
              CORE_LOGGER.debug('############# Pull docker image status: ##############')
            }
            // only write the status banner once, its cleaner
            let logText = ''
            if (progress.id) logText += progress.id + ' : ' + progress.status
            else logText = progress.status
            CORE_LOGGER.debug("Pulling image for jobId '" + job.jobId + "': " + logText)
            appendFileSync(imageLogFile, logText + '\n')
          }
        )
      })
      job.status = C2DStatusNumber.ConfiguringVolumes
      job.statusText = C2DStatusText.ConfiguringVolumes
      this.db.updateJob(job)
    } catch (err) {
      const logText = `Unable to pull docker image: ${job.containerImage}: ${err.message}`
      CORE_LOGGER.error(logText)
      appendFileSync(imageLogFile, logText)
      job.status = C2DStatusNumber.PullImageFailed
      job.statusText = C2DStatusText.PullImageFailed
      job.isRunning = false
      job.dateFinished = String(Date.now() / 1000)
      await this.db.updateJob(job)
      await this.cleanupJob(job)
    } finally {
      clearTimeout(timer)
      this.activeBuildAborts.delete(job.jobId)
    }
  }

  private async buildImage(
    originaljob: DBComputeJob,
    additionalDockerFiles: { [key: string]: any }
  ) {
    const job = JSON.parse(JSON.stringify(originaljob)) as DBComputeJob
    const imageLogFile = this.getStoragePath() + '/' + job.jobId + '/data/logs/image.log'
    const controller = new AbortController()
    const timeoutMs = job.maxJobDuration * 1000
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    this.activeBuildAborts.set(job.jobId, controller)
    try {
      const pack = tarStream.pack()

      // Append the Dockerfile to the tar archive
      pack.entry({ name: 'Dockerfile' }, job.algorithm.meta.container.dockerfile)
      // Append any additional files to the tar archive
      if (additionalDockerFiles) {
        for (const filePath of Object.keys(additionalDockerFiles)) {
          pack.entry({ name: filePath }, additionalDockerFiles[filePath])
        }
      }
      pack.finalize()
      job.buildStartTimestamp = String(Date.now() / 1000)
      await this.db.updateJob(job)

      const cpuperiod = 100000
      const ramGb = this.getResourceRequest(job.resources, 'ram')
      const ramBytes =
        ramGb && ramGb > 0 ? ramGb * 1024 * 1024 * 1024 : 1024 * 1024 * 1024

      const cpus = this.getResourceRequest(job.resources, 'cpu')
      const cpuquota = cpus && cpus > 0 ? Math.floor(cpus * cpuperiod) : 50000

      const buildOptions: Dockerode.ImageBuildOptions = {
        t: job.containerImage,
        memory: ramBytes,
        memswap: ramBytes, // same as memory => no swap
        cpushares: 1024, // CPU Shares (default is 1024)
        cpuquota, // 100000 = 1 CPU with cpuperiod=100000
        cpuperiod,
        nocache: true, // prevent cache poison
        abortSignal: controller.signal
      }
      // Build the image using the tar stream as context (Node IncomingMessage extends stream.Readable)
      const buildStream = (await this.docker.buildImage(pack, buildOptions)) as Readable

      const onBuildData = (data: Buffer) => {
        try {
          const text = JSON.parse(data.toString('utf8'))
          if (text && text.stream && typeof text.stream === 'string') {
            CORE_LOGGER.debug(
              "Building image for jobId '" + job.jobId + "': " + text.stream.trim()
            )
            appendFileSync(imageLogFile, String(text.stream))
          }
        } catch (e) {
          // console.log('non json build data: ', data.toString('utf8'))
        }
      }
      buildStream.on('data', onBuildData)

      await new Promise<void>((resolve, reject) => {
        let settled = false
        const detachBuildLog = () => {
          buildStream.removeListener('data', onBuildData)
        }
        const finish = (action: () => void) => {
          if (settled) return
          settled = true
          action()
        }
        const onAbort = () => {
          finish(() => {
            detachBuildLog()
            buildStream.destroy()
            const err = new Error('Image build aborted') as NodeJS.ErrnoException
            err.code = 'ABORT_ERR'
            err.name = 'AbortError'
            reject(err)
          })
        }
        controller.signal.addEventListener('abort', onAbort, { once: true })
        const onSuccess = () => {
          finish(async () => {
            detachBuildLog()
            controller.signal.removeEventListener('abort', onAbort)

            // Build stream completed, but does the image actually exist?
            try {
              await this.docker.getImage(job.containerImage).inspect()
            } catch (e) {
              return reject(
                new Error(
                  `Cannot find image '${job.containerImage}' after building. Most likely it failed: ${
                    (e as Error)?.message || String(e)
                  }`
                )
              )
            }

            CORE_LOGGER.debug(`Image '${job.containerImage}' built successfully.`)
            this.updateImageUsage(job.containerImage).catch((e) => {
              CORE_LOGGER.debug(`Failed to track image usage: ${e.message}`)
            })
            resolve()
          })
        }
        // Some HTTP responses emit `close` without a reliable `end`; handle both (settled ensures once).
        buildStream.on('end', onSuccess)
        buildStream.on('close', onSuccess)
        buildStream.on('error', (err) => {
          CORE_LOGGER.debug(`Error building image '${job.containerImage}':` + err.message)
          appendFileSync(imageLogFile, String(err.message))
          finish(() => {
            detachBuildLog()
            controller.signal.removeEventListener('abort', onAbort)
            reject(err)
          })
        })
      })
      job.status = C2DStatusNumber.ConfiguringVolumes
      job.statusText = C2DStatusText.ConfiguringVolumes
      job.buildStopTimestamp = String(Date.now() / 1000)
      await this.db.updateJob(job)
    } catch (err) {
      const aborted =
        (err as NodeJS.ErrnoException)?.code === 'ABORT_ERR' ||
        (err as Error)?.name === 'AbortError'
      if (aborted) {
        // timeout-specific handling
        const msg = `Image build timed out after ${timeoutMs / 1000}s`
        CORE_LOGGER.error(`Unable to build docker image: ${job.containerImage}: ${msg}`)
        appendFileSync(imageLogFile, msg)
      } else {
        CORE_LOGGER.error(
          `Unable to build docker image: ${job.containerImage}: ${err.message}`
        )
        appendFileSync(imageLogFile, String(err.message))
      }
      job.status = C2DStatusNumber.BuildImageFailed
      job.statusText = C2DStatusText.BuildImageFailed
      job.buildStopTimestamp = String(Date.now() / 1000)
      job.isRunning = false
      job.dateFinished = String(Date.now() / 1000)
      await this.db.updateJob(job)
      await this.cleanupJob(job)
    } finally {
      clearTimeout(timer)
      this.activeBuildAborts.delete(job.jobId)
    }
  }

  private addUserDataToFilesObject(
    filesObject: any,
    userData: { [key: string]: any }
  ): any {
    if (filesObject?.url && userData) {
      const url = new URL(filesObject.url)
      const userDataObj = typeof userData === 'string' ? JSON.parse(userData) : userData
      for (const [key, value] of Object.entries(userDataObj)) {
        url.searchParams.append(key, String(value))
      }
      filesObject.url = url.toString()
      CORE_LOGGER.info('Appended userData parameters to a file URL')
    }
    return filesObject
  }

  private async uploadData(
    job: DBComputeJob
  ): Promise<{ status: C2DStatusNumber; statusText: C2DStatusText }> {
    const config = this.getConfig()
    const ret = {
      status: C2DStatusNumber.RunningAlgorithm,
      statusText: C2DStatusText.RunningAlgorithm
    }
    const jobFolderPath = this.getStoragePath() + '/' + job.jobId
    const fullAlgoPath = jobFolderPath + '/data/transformations/algorithm'
    const configLogPath = jobFolderPath + '/data/logs/configuration.log'

    const jobEnvironment = await this.getJobEnvironment(job)
    if (!jobEnvironment) {
      CORE_LOGGER.error('Unable to resolve the compute environment during provisioning')
      appendFileSync(
        configLogPath,
        'Unable to resolve the compute environment during provisioning\n'
      )
      return {
        status: C2DStatusNumber.DataProvisioningFailed,
        statusText: C2DStatusText.DataProvisioningFailed
      }
    }
    const privateDatasetPolicy = this.privateDatasetPolicies.get(jobEnvironment.id)

    try {
      appendFileSync(
        configLogPath,
        "Writing algocustom data to '/data/inputs/algoCustomData.json'\n"
      )
      const customdataPath =
        this.getStoragePath() + '/' + job.jobId + '/data/inputs/algoCustomData.json'
      writeFileSync(customdataPath, JSON.stringify(job.algorithm.algocustomdata ?? {}))

      let storage = null

      if (job.algorithm.meta.rawcode && job.algorithm.meta.rawcode.length > 0) {
        // we have the code, just write it
        appendFileSync(configLogPath, `Writing raw algo code to ${fullAlgoPath}\n`)
        writeFileSync(fullAlgoPath, job.algorithm.meta.rawcode)
      } else {
        // do we have a files object?
        if (job.algorithm.fileObject) {
          // is it unencrypted?
          if (job.algorithm.fileObject.type) {
            // we can get the storage directly
            try {
              storage = Storage.getStorageClass(job.algorithm.fileObject, config)
            } catch (e) {
              CORE_LOGGER.error(`Unable to get storage class for algorithm: ${e.message}`)
              appendFileSync(
                configLogPath,
                `Unable to get storage class for algorithm: ${e.message}\n`
              )
              return {
                status: C2DStatusNumber.AlgorithmProvisioningFailed,
                statusText: C2DStatusText.AlgorithmProvisioningFailed
              }
            }
          } else {
            // ok, maybe we have this encrypted instead
            CORE_LOGGER.info(
              'algorithm file object seems to be encrypted, checking it...'
            )
            // 1. Decrypt the files object
            try {
              const decryptedFileObject = await decryptFilesObject(
                job.algorithm.fileObject
              )
              storage = Storage.getStorageClass(decryptedFileObject, config)
            } catch (e) {
              CORE_LOGGER.error(`Unable to decrypt algorithm files object: ${e.message}`)
              appendFileSync(
                configLogPath,
                `Unable to decrypt algorithm files object: ${e.message}\n`
              )
              return {
                status: C2DStatusNumber.AlgorithmProvisioningFailed,
                statusText: C2DStatusText.AlgorithmProvisioningFailed
              }
            }
          }
        } else {
          // no files object, try to get information from documentId and serviceId
          CORE_LOGGER.info(
            'algorithm file object seems to be missing, checking "serviceId" and "documentId"...'
          )
          const { serviceId, documentId } = job.algorithm
          appendFileSync(
            configLogPath,
            `Using ${documentId} and serviceId ${serviceId} to get algorithm files.\n`
          )
          // we can get it from this info
          if (serviceId && documentId) {
            const algoDdo = await new FindDdoHandler(
              OceanNode.getInstance()
            ).findAndFormatDdo(documentId)
            // 1. Get the service
            const service: Service = AssetUtils.getServiceById(algoDdo, serviceId)
            if (!service) {
              CORE_LOGGER.error(
                `Could not find service with ID ${serviceId} in DDO ${documentId}`
              )
              appendFileSync(
                configLogPath,
                `Could not find service with ID ${serviceId} in DDO ${documentId}\n`
              )
              return {
                status: C2DStatusNumber.AlgorithmProvisioningFailed,
                statusText: C2DStatusText.AlgorithmProvisioningFailed
              }
            }
            try {
              // 2. Decrypt the files object
              const decryptedFileObject = await decryptFilesObject(service.files)
              storage = Storage.getStorageClass(decryptedFileObject, config)
            } catch (e) {
              CORE_LOGGER.error(`Unable to decrypt algorithm files object: ${e.message}`)
              appendFileSync(
                configLogPath,
                `Unable to decrypt algorithm files object: ${e.message}\n`
              )
              return {
                status: C2DStatusNumber.AlgorithmProvisioningFailed,
                statusText: C2DStatusText.AlgorithmProvisioningFailed
              }
            }
          }
        }

        if (storage) {
          await pipeline(
            (await storage.getReadableStream()).stream,
            createWriteStream(fullAlgoPath)
          )
        } else {
          CORE_LOGGER.info(
            'Could not extract any files object from the compute algorithm, skipping...'
          )
          appendFileSync(
            configLogPath,
            'Could not extract any files object from the compute algorithm, skipping...\n'
          )
        }
      }
    } catch (e) {
      CORE_LOGGER.error(
        'Unable to write algorithm to path: ' + fullAlgoPath + ': ' + e.message
      )
      appendFileSync(
        configLogPath,
        'Unable to write algorithm to path: ' + fullAlgoPath + ': ' + e.message + '\n'
      )
      return {
        status: C2DStatusNumber.AlgorithmProvisioningFailed,
        statusText: C2DStatusText.AlgorithmProvisioningFailed
      }
    }

    // now for the assets
    for (const i in job.assets) {
      const asset = job.assets[i]
      let storage = null
      let fileInfo = null
      appendFileSync(configLogPath, `Downloading asset ${i} to /data/inputs/\n`)
      // without this check it would break if no fileObject is present
      if (asset.fileObject) {
        try {
          if (asset.fileObject.type) {
            if (asset.fileObject.type === 'nodePersistentStorage') {
              if (privateDatasetPolicy) {
                throw new Error('private_dataset_storage_type_invalid')
              }
              // local storage is handled later, when we start the container and create the binds
              continue
            }
            storage = Storage.getStorageClass(asset.fileObject, config)
          } else {
            CORE_LOGGER.info('asset file object seems to be encrypted, checking it...')
            // get the encrypted bytes
            let filesObject: any = await decryptFilesObject(asset.fileObject)
            filesObject = await this.addUserDataToFilesObject(filesObject, asset.userdata)
            storage = Storage.getStorageClass(filesObject, config)
          }

          // we need the file info for the name (but could be something else here)
          if (!privateDatasetPolicy) {
            fileInfo = await storage.getFileInfo({
              type: storage.getStorageType(asset.fileObject)
            })
          }
        } catch (e) {
          CORE_LOGGER.error(`Unable to get storage class for asset: ${e.message}`)
          appendFileSync(
            configLogPath,
            `Unable to get storage class for asset: ${e.message}\n`
          )
          return {
            status: C2DStatusNumber.DataProvisioningFailed,
            statusText: C2DStatusText.DataProvisioningFailed
          }
        }
      } else {
        // we need to go the hard way
        const { serviceId, documentId } = asset
        appendFileSync(
          configLogPath,
          `Using ${documentId} and serviceId ${serviceId} for this asset.\n`
        )
        if (serviceId && documentId) {
          // need to get the file
          try {
            const ddo = await new FindDdoHandler(
              OceanNode.getInstance()
            ).findAndFormatDdo(documentId)
            // 2. Get the service
            const service: Service = AssetUtils.getServiceById(ddo, serviceId)
            // 3. Decrypt the url
            let decryptedFileObject = await decryptFilesObject(service.files)
            decryptedFileObject = await this.addUserDataToFilesObject(
              decryptedFileObject,
              asset.userdata
            )
            storage = Storage.getStorageClass(decryptedFileObject, config)
            if (!privateDatasetPolicy) {
              fileInfo = await storage.getFileInfo({
                type: storage.getStorageType(decryptedFileObject)
              })
            }
          } catch (e) {
            CORE_LOGGER.error(`Unable to get storage class for asset: ${e.message}`)
            appendFileSync(
              configLogPath,
              `Unable to get storage class for asset: ${e.message}\n`
            )
            return {
              status: C2DStatusNumber.DataProvisioningFailed,
              statusText: C2DStatusText.DataProvisioningFailed
            }
          }
        }
      }

      if (storage && privateDatasetPolicy) {
        const fullPath = jobFolderPath + '/data/inputs/dataset.json'
        appendFileSync(configLogPath, 'Downloading verified private dataset\n')
        try {
          await downloadPrivateDataset(
            storage.getFile() as UrlFileObject,
            fullPath,
            job.jobId,
            privateDatasetPolicy
          )
        } catch (e) {
          CORE_LOGGER.error(`Unable to provision private dataset: ${e.message}`)
          appendFileSync(
            configLogPath,
            `Unable to provision private dataset: ${e.message}\n`
          )
          return {
            status: C2DStatusNumber.DataProvisioningFailed,
            statusText: C2DStatusText.DataProvisioningFailed
          }
        }
      } else if (storage && fileInfo) {
        const fullPath = jobFolderPath + '/data/inputs/' + fileInfo[0].name
        appendFileSync(configLogPath, `Downloading asset to ${fullPath}\n`)
        try {
          await pipeline(
            (await storage.getReadableStream()).stream,
            createWriteStream(fullPath)
          )
        } catch (e) {
          CORE_LOGGER.error(
            'Unable to write input data to path: ' + fullPath + ': ' + e.message
          )
          appendFileSync(
            configLogPath,
            'Unable to write input data to path: ' + fullPath + ': ' + e.message + '\n'
          )
          return {
            status: C2DStatusNumber.DataProvisioningFailed,
            statusText: C2DStatusText.DataProvisioningFailed
          }
        }
      } else {
        CORE_LOGGER.info(
          'Could not extract any files object from the compute asset, skipping...'
        )
        appendFileSync(
          configLogPath,
          'Could not extract any files object from the compute asset, skipping...\n'
        )
      }
    }
    CORE_LOGGER.info('All good with data provisioning, will start uploading it...')
    appendFileSync(
      configLogPath,
      'All good with data provisioning, will start uploading it...\n'
    )
    // now, we have to create a tar arhive
    const folderToTar = jobFolderPath + '/data'
    const destination = jobFolderPath + '/tarData/upload.tar.gz'
    try {
      tar.create(
        {
          gzip: true,
          file: destination,
          sync: true,
          C: folderToTar
        },
        ['./']
      )
      // check if tar.gz actually exists

      if (existsSync(destination)) {
        // now, upload it to the container
        const container = this.docker.getContainer(job.jobId + '-algoritm')

        try {
          // await container2.putArchive(destination, {
          await container.putArchive(destination, {
            path: '/data'
          })
        } catch (e) {
          appendFileSync(
            configLogPath,
            'Data upload to container failed: ' + e.message + '\n'
          )
          return {
            status: C2DStatusNumber.DataUploadFailed,
            statusText: C2DStatusText.DataUploadFailed
          }
        }
      } else {
        CORE_LOGGER.debug('No data to upload, empty tar.gz')
        appendFileSync(configLogPath, `No data to upload, empty tar.gz\n`)
      }
    } catch (e) {
      CORE_LOGGER.debug(e.message)
      appendFileSync(configLogPath, `Error creating data archive: ${e.message}\n`)
      return {
        status: C2DStatusNumber.DataProvisioningFailed,
        statusText: C2DStatusText.DataProvisioningFailed
      }
    }

    rmSync(jobFolderPath + '/data/inputs', {
      recursive: true,
      force: true
    })
    rmSync(jobFolderPath + '/data/transformations', {
      recursive: true,
      force: true
    })
    rmSync(jobFolderPath + '/tarData', {
      recursive: true,
      force: true
    })
    return ret
  }

  private makeJobFolders(job: DBComputeJob): boolean {
    try {
      const baseFolder = this.getStoragePath() + '/' + job.jobId
      const dirs = [
        baseFolder,
        baseFolder + '/data',
        baseFolder + '/data/inputs',
        baseFolder + '/data/transformations',
        baseFolder + '/data/ddos',
        baseFolder + '/data/outputs',
        baseFolder + '/data/logs',
        baseFolder + '/tarData'
      ]
      for (const dir of dirs) {
        if (!existsSync(dir)) {
          mkdirSync(dir, { recursive: true })
        }
        // update directory permissions to allow read/write from job containers
        chmodSync(dir, 0o777)
      }
      return true
    } catch (e) {
      CORE_LOGGER.error('Failed to create folders needed for the job: ' + e.message)
      return false
    }
  }

  // clean up temporary files
  public override async cleanupExpiredStorage(
    job: DBComputeJob,
    isCleanAfterDownload: boolean = false
  ): Promise<boolean> {
    if (!job) return false
    CORE_LOGGER.info('Cleaning up C2D storage for Job: ' + job.jobId)
    try {
      // delete the storage
      // for free env, the container is deleted as soon as we download the results
      // so we avoid trying to do it again
      if (!isCleanAfterDownload) {
        await this.cleanupJob(job)
      }

      // delete output folders
      this.deleteOutputFolder(job)
      // delete the job
      await this.db.deleteJob(job.jobId)
      return true
    } catch (e) {
      CORE_LOGGER.error('Error cleaning up C2D storage and Job: ' + e.message)
    }
    return false
  }

  private getValidBuildDurationSeconds(job: DBComputeJob): number {
    const startRaw = job.buildStartTimestamp
    const stopRaw = job.buildStopTimestamp
    if (!startRaw || !stopRaw) return 0
    const start = Number.parseFloat(startRaw)
    const stop = Number.parseFloat(stopRaw)
    if (!Number.isFinite(start) || !Number.isFinite(stop)) return 0
    if (start <= 0) return 0
    if (stop < start) return 0
    return stop - start
  }

  private async checkscanDBImage(): Promise<void> {
    try {
      await this.docker.getImage(trivyImage).inspect()
    } catch (error) {
      if (error.statusCode !== 404) {
        throw new Error(`Unable to inspect ${trivyImage}: ${error.message}`)
      }
      CORE_LOGGER.info(`Trivy not found. Pulling ${trivyImage}...`)
      const stream = await this.docker.pull(trivyImage)
      await new Promise((resolve, reject) => {
        this.docker.modem.followProgress(stream, (err, res) =>
          err ? reject(err) : resolve(res)
        )
      })
      await this.docker.getImage(trivyImage).inspect()
      CORE_LOGGER.info('Pull complete.')
    }
  }

  private async scanDBUpdate(): Promise<void> {
    CORE_LOGGER.info('Starting Trivy database refresh cron')
    await this.checkscanDBImage()
    let updater: Dockerode.Container = null
    try {
      updater = await this.docker.createContainer({
        Image: trivyImage,
        Cmd: ['image', '--download-db-only'],
        HostConfig: {
          Binds: [`${this.trivyCachePath}:/root/.cache/trivy`]
        }
      })
      await updater.start()
      const result = await updater.wait()
      if (result?.StatusCode !== 0) {
        throw new Error(`Trivy database update exited with status ${result?.StatusCode}`)
      }
      CORE_LOGGER.info('Trivy database refreshed.')
    } finally {
      if (updater) await updater.remove({ force: true }).catch((): void => undefined)
    }
  }

  private async scanImage(imageName: string): Promise<unknown> {
    if (!imageName || !imageName.trim()) throw new Error('Image name is empty')
    await this.checkscanDBImage()
    CORE_LOGGER.debug(`Starting vulnerability check for ${imageName}`)
    let container: Dockerode.Container = null
    try {
      container = await this.docker.createContainer({
        Image: trivyImage,
        Cmd: [
          'image',
          '--format',
          'json',
          '--quiet',
          '--no-progress',
          '--skip-db-update',
          '--severity',
          this.scanImageRejectSeverities.join(','),
          imageName
        ],
        HostConfig: {
          Binds: [
            '/var/run/docker.sock:/var/run/docker.sock',
            `${this.trivyCachePath}:/root/.cache/trivy`
          ]
        }
      })
      await container.start()
      const logsStream = await container.logs({
        follow: true,
        stdout: true,
        stderr: true
      })
      const outStream = new PassThrough()
      const errStream = new PassThrough()
      outStream.resume()
      errStream.resume()

      const rawChunks: Buffer[] = []
      const errorChunks: Buffer[] = []
      let reportBytes = 0
      let errorBytes = 0
      let reportTooLarge = false
      outStream.on('data', (chunk) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
        reportBytes += buffer.length
        if (reportBytes > MAX_TRIVY_REPORT_BYTES) reportTooLarge = true
        else rawChunks.push(buffer)
      })
      errStream.on('data', (chunk) => {
        if (errorBytes >= 4096) return
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
        const bounded = buffer.subarray(0, 4096 - errorBytes)
        errorChunks.push(bounded)
        errorBytes += bounded.length
      })
      container.modem.demuxStream(logsStream, outStream, errStream)

      const logsDrained = new Promise<void>((resolve, reject) => {
        const done = () => resolve()
        logsStream.once('end', done)
        logsStream.once('close', done)
        logsStream.once('error', reject)
      })
      const scanResult = await container.wait()
      await logsDrained

      if (scanResult?.StatusCode !== 0) {
        const stderr = Buffer.concat(errorChunks).toString('utf8').slice(0, 4096)
        throw new Error(
          `Trivy exited with status ${scanResult?.StatusCode}${stderr ? `: ${stderr}` : ''}`
        )
      }
      if (reportTooLarge) throw new Error('Trivy report exceeds the size limit')

      const reportBuffer = Buffer.concat(rawChunks)
      if (reportBuffer.length === 0) throw new Error('Trivy returned an empty report')
      let reportText: string
      try {
        reportText = new TextDecoder('utf-8', { fatal: true }).decode(reportBuffer)
      } catch {
        throw new Error('Trivy report is not valid UTF-8')
      }
      let report: unknown
      try {
        report = JSON.parse(reportText)
      } catch {
        throw new Error('Trivy report is not valid JSON')
      }
      CORE_LOGGER.debug(`Vulnerability check for ${imageName} finished`)
      return report
    } finally {
      if (container) await container.remove({ force: true }).catch((): void => undefined)
    }
  }

  private async checkImageVulnerability(imageName: string) {
    const report = await this.scanImage(imageName)
    return evaluateTrivyReport(report, this.scanImageRejectSeverities)
  }
}

// this uses the docker engine, but exposes only one env, the free one

export function getAlgorithmImage(algorithm: ComputeAlgorithm, jobId: string): string {
  if (!algorithm.meta || !algorithm.meta.container) {
    return null
  }
  if (algorithm.meta.container.dockerfile) {
    return jobId.toLowerCase() + '-image:latest'
  }
  let { image } = algorithm.meta.container
  if (algorithm.meta.container.checksum)
    image = image + '@' + algorithm.meta.container.checksum
  else if (algorithm.meta.container.tag)
    image = image + ':' + algorithm.meta.container.tag
  else image = image + ':latest'
  // console.log('Using image: ' + image)
  return image
}

export function checkManifestPlatform(
  manifestPlatform: any,
  envPlatform?: RunningPlatform
): boolean {
  if (!manifestPlatform || !envPlatform) return true // skips if not present

  const normalizeArchitecture = (architecture: string): string => {
    if (architecture === 'amd64' || architecture === 'x86_64') return 'amd64'
    if (architecture === 'arm64' || architecture === 'aarch64') return 'arm64'
    return architecture
  }

  if (
    normalizeArchitecture(envPlatform.architecture) !==
      normalizeArchitecture(manifestPlatform.architecture) ||
    envPlatform.os !== manifestPlatform.os
  )
    return false
  return true
}
