import { z } from 'zod'
import { getAddress } from 'ethers'
import { dhtFilterMethod } from '../../@types/OceanNode.js'
import { C2DClusterType } from '../../@types/C2D/C2D.js'
import { CONFIG_LOGGER } from '../logging/common.js'
import { booleanFromString, jsonFromString } from './transforms.js'
import {
  DEFAULT_BOOTSTRAP_ADDRESSES,
  DEFAULT_RATE_LIMIT_PER_MINUTE,
  DEFAULT_UNSAFE_URLS,
  DEFAULT_FILTER_ANNOUNCED_ADDRESSES
} from './constants.js'

function isValidUrl(urlString: string): boolean {
  try {
    // eslint-disable-next-line no-new
    new URL(urlString)
    return true
  } catch {
    return false
  }
}

function isValidTlsServerName(value: string): boolean {
  if (value.length < 1 || value.length > 253) return false
  const labels = value.split('.')
  for (const label of labels) {
    if (label.length < 1 || label.length > 63) return false
    if (label.startsWith('-') || label.endsWith('-')) return false
    for (const character of label) {
      const code = character.charCodeAt(0)
      const isDigit = code >= 48 && code <= 57
      const isUppercase = code >= 65 && code <= 90
      const isLowercase = code >= 97 && code <= 122
      if (!isDigit && !isUppercase && !isLowercase && character !== '-') return false
    }
  }
  return true
}

function isLocalProofHostname(value: string): boolean {
  const parts = value.split('.')
  const loopbackIpv4 =
    parts.length === 4 &&
    parts[0] === '127' &&
    parts.every(
      (part) =>
        part.length > 0 &&
        [...part].every((character) => character >= '0' && character <= '9') &&
        Number(part) <= 255
    )
  return (
    value === 'localhost' ||
    loopbackIpv4 ||
    (!value.includes('.') && isValidTlsServerName(value))
  )
}

export const SupportedNetworkSchema = z.object({
  chainId: z.number(),
  rpc: z.string(),
  network: z.string().optional(),
  chunkSize: z.number().optional(),
  startBlock: z.number().optional(),
  fallbackRPCs: z.array(z.string()).optional()
})

export const RPCSSchema = z.record(z.string(), SupportedNetworkSchema)

export const AccessListContractSchema = z.preprocess(
  (val) => {
    // If it's not a plain object, normalize to null
    if (val === null) return null
    // If it's a JSON string, try to parse it
    if (typeof val === 'string') {
      try {
        val = JSON.parse(val)
      } catch {
        return null
      }
    }

    if (typeof val !== 'object' || Array.isArray(val)) return null

    return val
  },
  z.record(z.string(), z.array(z.string())).nullable()
)

export const OceanNodeConfigKeysSchema = z.object({
  privateKey: z.any().optional().nullable(),
  type: z.string().optional().default('raw')
})

export const DenyListSchema = z.object({
  peers: z.array(z.string()).default([]),
  ips: z.array(z.string()).default([])
})

export const FeeAmountSchema = z.object({
  amount: z.number(),
  unit: z.string()
})

export const FeeTokensSchema = z.object({
  chain: z.string(),
  token: z.string()
})

export const FeeStrategySchema = z.object({
  feeTokens: z.array(FeeTokensSchema).optional(),
  feeAmount: FeeAmountSchema.optional()
})

export const OceanNodeDBConfigSchema = z.object({
  url: z.string().nullable(),
  username: z.string().optional(),
  password: z.string().optional(),
  dbType: z.string().nullable()
})

export const PersistentStorageConfigSchema = z
  .object({
    enabled: z.boolean().optional().default(false),
    type: z.enum(['localfs', 's3']).optional().default('localfs'),
    accessLists: jsonFromString(z.array(z.record(z.string(), z.array(z.string()))))
      .optional()
      .default([]),
    options: z.any().optional()
  })
  .superRefine((data, ctx) => {
    if (!data.enabled) return

    if (data.type === 'localfs') {
      if (!data.options || typeof data.options !== 'object') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'persistentStorage.options must be an object for localfs',
          path: ['options']
        })
        return
      }
      if (
        typeof (data.options as any).folder !== 'string' ||
        !(data.options as any).folder
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'persistentStorage.options.folder is required for localfs',
          path: ['options', 'folder']
        })
      }
    }

    if (data.type === 's3') {
      if (!data.options || typeof data.options !== 'object') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'persistentStorage.options must be an object for s3',
          path: ['options']
        })
        return
      }
      const required = ['endpoint', 'objectKey', 'accessKeyId', 'secretAccessKey']
      for (const key of required) {
        if (
          typeof (data.options as any)[key] !== 'string' ||
          !(data.options as any)[key]
        ) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `persistentStorage.options.${key} is required for s3`,
            path: ['options', key]
          })
        }
      }
    }
  })

export const DockerRegistryAuthSchema = z
  .object({
    username: z.string().optional(),
    password: z.string().optional(),
    auth: z.string().optional()
  })
  .refine(
    (data) => {
      // Either 'auth' is provided, OR both 'username' and 'password' are provided
      return (
        (data.auth !== undefined && data.auth !== '') ||
        (data.username !== undefined &&
          data.username !== '' &&
          data.password !== undefined &&
          data.password !== '')
      )
    },
    {
      message:
        "Either 'auth' must be provided, or both 'username' and 'password' must be provided"
    }
  )

export const DockerRegistrysSchema = z.record(z.string(), DockerRegistryAuthSchema)

const ResourceConstraintSchema = z.object({
  id: z.string(),
  min: z.number().optional(),
  max: z.number().optional()
})

export const ComputeResourceSchema = z.object({
  id: z.string(),
  total: z.number().optional(),
  description: z.string().optional(),
  type: z.string().optional(),
  kind: z.string().optional(),
  min: z.number().optional(),
  max: z.number().optional(),
  inUse: z.number().optional(),
  init: z.any().optional(),
  platform: z.string().optional(),
  memoryTotal: z.string().optional(),
  driverVersion: z.string().optional(),
  constraints: z.array(ResourceConstraintSchema).optional()
})

export const ComputeResourcesPricingInfoSchema = z.object({
  id: z.string(),
  price: z.number()
})

export const ComputeEnvFeesSchema = z.object({
  feeToken: z.string().optional(),
  prices: z.array(ComputeResourcesPricingInfoSchema).optional()
})

export const ComputeEnvironmentFreeOptionsSchema = z.object({
  minJobDuration: z.number().int().optional().default(60),
  maxJobDuration: z.number().int().optional().default(3600),
  maxJobs: z.number().int().optional().default(3),
  resources: z.array(ComputeResourceSchema).optional(),
  access: z
    .object({
      addresses: z.array(z.string()),
      accessLists: z
        .array(z.record(z.string(), z.array(z.string())))
        .nullable()
        .optional()
    })
    .optional(),
  allowImageBuild: z.boolean().optional().default(false)
})

export const ConsumerResultPolicySchema = z.discriminatedUnion('mode', [
  z.object({ mode: z.literal('archive') }).strict(),
  z
    .object({
      mode: z.literal('singleJson'),
      maxBytes: z
        .number()
        .int()
        .positive()
        .max(10 * 1024 * 1024),
      resultContract: z
        .enum(['brainstem.c2d-result/v1', 'brainstem.insight-result/v1'])
        .optional()
    })
    .strict()
])

export const C2DEnvironmentConfigSchema = z
  .object({
    id: z.string().optional(),
    description: z.string().optional(),
    storageExpiry: z.number().int().optional().default(604800),
    minJobDuration: z.number().int().optional().default(60),
    maxJobDuration: z.number().int().optional().default(3600),
    maxJobs: z.number().int().optional(),
    fees: z.record(z.string(), z.array(ComputeEnvFeesSchema)).optional(),
    access: z
      .object({
        addresses: z.array(z.string()),
        accessLists: z
          .array(z.record(z.string(), z.array(z.string())))
          .nullable()
          .optional()
      })
      .optional(),
    free: ComputeEnvironmentFreeOptionsSchema.optional(),
    resources: z.array(ComputeResourceSchema).optional(),
    enableNetwork: z.boolean().optional().default(false),
    consumerResultPolicy: ConsumerResultPolicySchema,
    privateDataset: z
      .object({
        analysisId: z.enum([
          'brainstem.resting-rr-cohort-summary/v1',
          'brainstem.resting-hrv-methods/v1',
          'brainstem.resting-rr-sample-entropy/v1',
          'brainstem.overnight-heart-rate-change/v1',
          'brainstem.resting-hrv-repeatability/v1',
          'brainstem.standing-heart-rate-response/v1',
          'brainstem.guided-breathing-response/v1'
        ]),
        url: z
          .string()
          .url()
          .refine((value) => {
            const parsed = new URL(value)
            return !parsed.username && !parsed.password && !parsed.search && !parsed.hash
          }, 'private dataset URL must not contain credentials, query, or fragment'),
        maxBytes: z
          .number()
          .int()
          .min(1)
          .max(16 * 1024 * 1024),
        approvedAlgorithmImage: z
          .string()
          .regex(/^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$/),
        bearerTokenEnv: z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/),
        releaseId: z.string().regex(/^[0-9a-f]{64}$/),
        paperInsight: z
          .object({
            algorithmVersion: z.literal('0.1.0'),
            inputSchema: z.enum([
              'brainstem.resting-hrv-methods-cohort/v1',
              'brainstem.resting-sample-entropy-cohort/v1',
              'brainstem.overnight-heart-rate-change-cohort/v1',
              'brainstem.resting-hrv-repeatability-cohort/v1',
              'brainstem.standing-heart-rate-response-cohort/v1',
              'brainstem.guided-breathing-response-cohort/v1'
            ]),
            candidateManifestSha256: z.string().regex(/^[0-9a-f]{64}$/),
            approvedManifestSha256: z.string().regex(/^[0-9a-f]{64}$/),
            referenceSha256: z
              .string()
              .regex(/^[0-9a-f]{64}$/)
              .nullable(),
            evidenceTier: z.enum([
              'E0_candidate',
              'E1_public_reproduced',
              'E2_brainstem_compatible_exploratory'
            ]),
            useClass: z.literal('methods_only'),
            clinicalUse: z.literal('prohibited')
          })
          .strict()
          .optional(),
        participantValue: z
          .object({
            crabSignerAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/)
          })
          .strict()
          .optional(),
        tls: z
          .object({
            caFile: z
              .string()
              .regex(/^\/run\/brainstem-secrets\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/),
            clientCertificateFile: z
              .string()
              .regex(/^\/run\/brainstem-secrets\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/),
            clientKeyFile: z
              .string()
              .regex(/^\/run\/brainstem-secrets\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/),
            serverName: z.string().refine(isValidTlsServerName, 'invalid TLS server name')
          })
          .strict()
          .optional()
      })
      .strict()
      .refine(
        (policy) => {
          if (policy.analysisId === 'brainstem.resting-hrv-methods/v1') {
            return (
              policy.paperInsight?.inputSchema ===
                'brainstem.resting-hrv-methods-cohort/v1' &&
              policy.paperInsight.candidateManifestSha256 ===
                '15dbf8544c87d81c06f5e512b00e9fe39dd6431dd1a4079a97da68a3f92721c1' &&
              policy.participantValue === undefined
            )
          }
          if (policy.analysisId === 'brainstem.resting-rr-sample-entropy/v1') {
            return (
              policy.paperInsight?.inputSchema ===
                'brainstem.resting-sample-entropy-cohort/v1' &&
              policy.paperInsight.candidateManifestSha256 ===
                '65002ab13f02f812c611085c0295b81dc90ec7ffacc79f9ff4927e81e9070bdd' &&
              policy.participantValue === undefined
            )
          }
          if (policy.analysisId === 'brainstem.overnight-heart-rate-change/v1') {
            return (
              policy.paperInsight?.inputSchema ===
                'brainstem.overnight-heart-rate-change-cohort/v1' &&
              policy.paperInsight.candidateManifestSha256 ===
                '11accac777e72b9ee566531f174658d47fc211992223b5285f97fb7c003088f7' &&
              policy.paperInsight.referenceSha256 === null &&
              policy.paperInsight.evidenceTier === 'E1_public_reproduced' &&
              policy.participantValue === undefined
            )
          }
          if (policy.analysisId === 'brainstem.resting-hrv-repeatability/v1') {
            return (
              policy.paperInsight?.inputSchema ===
                'brainstem.resting-hrv-repeatability-cohort/v1' &&
              policy.paperInsight.candidateManifestSha256 ===
                '09e22348e350bb9e1da7183929675f7d67e718eb183075a7735c5513468905dd' &&
              policy.paperInsight.referenceSha256 === null &&
              policy.paperInsight.evidenceTier === 'E0_candidate' &&
              policy.participantValue === undefined
            )
          }
          if (policy.analysisId === 'brainstem.standing-heart-rate-response/v1') {
            return (
              policy.paperInsight?.inputSchema ===
                'brainstem.standing-heart-rate-response-cohort/v1' &&
              policy.paperInsight.candidateManifestSha256 ===
                'ee503af519ed241f1f7ec965b58ad41b38c622c71a43e3f44c86743722ac4217' &&
              policy.paperInsight.referenceSha256 === null &&
              policy.paperInsight.evidenceTier ===
                'E2_brainstem_compatible_exploratory' &&
              policy.participantValue === undefined
            )
          }
          if (policy.analysisId === 'brainstem.guided-breathing-response/v1') {
            return (
              policy.paperInsight?.inputSchema ===
                'brainstem.guided-breathing-response-cohort/v1' &&
              policy.paperInsight.candidateManifestSha256 ===
                'e64490c6539db744350ee761db4a1fedffd6f9f631f8814480a684c1fdc4931d' &&
              policy.paperInsight.referenceSha256 === null &&
              policy.paperInsight.evidenceTier ===
                'E2_brainstem_compatible_exploratory' &&
              policy.participantValue === undefined
            )
          }
          return policy.paperInsight === undefined
        },
        {
          message: 'The reviewed paper policy must match the named cohort analysis'
        }
      )
      .optional(),
    personalInsight: z
      .object({
        analysisId: z.enum([
          'brainstem.personal-resting-heart-overview/v1',
          'brainstem.resting-hrv-methods/v1',
          'brainstem.resting-rr-sample-entropy/v1',
          'brainstem.sleep-baseline/v1',
          'brainstem.overnight-heart-rate-change/v1',
          'brainstem.resting-hrv-repeatability/v1',
          'brainstem.standing-heart-rate-response/v1',
          'brainstem.guided-breathing-response/v1'
        ]),
        algorithmVersion: z.enum(['1.0.0', '0.1.0']),
        crabUrl: z
          .string()
          .url()
          .refine((value) => {
            const parsed = new URL(value)
            return (
              !parsed.username &&
              !parsed.password &&
              !parsed.search &&
              !parsed.hash &&
              parsed.pathname === '/'
            )
          }, 'personal Insight Crab URL must be a credential-free origin'),
        approvedAlgorithmImage: z
          .string()
          .regex(/^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$/),
        candidateManifestSha256: z
          .string()
          .regex(/^[0-9a-f]{64}$/)
          .nullable(),
        approvedManifestSha256: z
          .string()
          .regex(/^[0-9a-f]{64}$/)
          .nullable(),
        referenceSha256: z
          .string()
          .regex(/^[0-9a-f]{64}$/)
          .nullable(),
        evidenceTier: z.enum([
          'E0_candidate',
          'E1_public_reproduced',
          'E2_brainstem_compatible_exploratory'
        ]),
        useClass: z.literal('methods_only'),
        clinicalUse: z.literal('prohibited'),
        bearerTokenEnv: z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/),
        bffBearerTokenEnv: z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/),
        ramWorkspaceRoot: z
          .string()
          .regex(/^\/dev\/shm\/[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/),
        inputSchema: z.enum([
          'brainstem.personal-resting-rr/v1',
          'brainstem.personal-resting-hrv-methods/v1',
          'brainstem.personal-resting-sample-entropy/v1',
          'brainstem.personal-sleep-baseline/v1',
          'brainstem.personal-overnight-heart-rate-change/v1',
          'brainstem.personal-resting-hrv-repeatability/v1',
          'brainstem.personal-standing-heart-rate-response/v1',
          'brainstem.personal-guided-breathing-response/v1'
        ]),
        inputPolicy: z.enum([
          'brainstem.personal-resting-rr/latest-16/v1',
          'brainstem.personal-resting-hrv-methods/latest-16/v1',
          'brainstem.personal-resting-sample-entropy/latest-4/v1',
          'brainstem.personal-sleep-baseline/latest-7/v1',
          'brainstem.personal-overnight-heart-rate-change/latest-distinct-9/v1',
          'brainstem.personal-resting-hrv-repeatability/latest-distinct-7/v1',
          'brainstem.personal-standing-heart-rate-response/latest-7/v1',
          'brainstem.personal-guided-breathing-response/protocol-6-5-0-5-0/latest-7/v1'
        ]),
        resultContract: z.enum([
          'brainstem.c2d-result/v1',
          'brainstem.insight-result/v1'
        ]),
        resultProfile: z.enum([
          'brainstem.personal-resting-heart-overview/v1',
          'brainstem.resting-hrv-methods-personal/v1',
          'brainstem.resting-sample-entropy-personal/v1',
          'brainstem.sleep-baseline-personal/v1',
          'brainstem.overnight-heart-rate-change-personal/v1',
          'brainstem.resting-hrv-repeatability-personal/v1',
          'brainstem.standing-heart-rate-response-personal/v1',
          'brainstem.guided-breathing-response-personal/v1'
        ]),
        audience: z.literal('brainstem-ocean-node'),
        maximumRecordings: z.union([
          z.literal(4),
          z.literal(7),
          z.literal(9),
          z.literal(16)
        ]),
        maxInputBytes: z
          .number()
          .int()
          .min(1)
          .max(8 * 1024 * 1024),
        maxResultBytes: z
          .number()
          .int()
          .min(1)
          .max(256 * 1024),
        maxJobDuration: z.number().int().min(1).max(300),
        resources: z
          .object({
            cpu: z.number().int().min(1),
            ram: z.number().int().min(1)
          })
          .strict(),
        allowInsecureLocalProof: z.boolean().optional().default(false),
        tls: z
          .object({
            caFile: z
              .string()
              .regex(/^\/run\/brainstem-secrets\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/),
            clientCertificateFile: z
              .string()
              .regex(/^\/run\/brainstem-secrets\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/),
            clientKeyFile: z
              .string()
              .regex(/^\/run\/brainstem-secrets\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/),
            serverName: z.string().refine(isValidTlsServerName, 'invalid TLS server name')
          })
          .strict()
          .optional()
      })
      .strict()
      .superRefine((policy, context) => {
        const url = new URL(policy.crabUrl)
        const legacy =
          policy.analysisId === 'brainstem.personal-resting-heart-overview/v1'
        const methods = policy.analysisId === 'brainstem.resting-hrv-methods/v1'
        const sampleEntropy =
          policy.analysisId === 'brainstem.resting-rr-sample-entropy/v1'
        const overnight = policy.analysisId === 'brainstem.overnight-heart-rate-change/v1'
        const repeatability =
          policy.analysisId === 'brainstem.resting-hrv-repeatability/v1'
        const standing = policy.analysisId === 'brainstem.standing-heart-rate-response/v1'
        const guidedBreathing =
          policy.analysisId === 'brainstem.guided-breathing-response/v1'
        const exactPolicy = legacy
          ? policy.maximumRecordings === 16 &&
            policy.algorithmVersion === '1.0.0' &&
            policy.inputSchema === 'brainstem.personal-resting-rr/v1' &&
            policy.inputPolicy === 'brainstem.personal-resting-rr/latest-16/v1' &&
            policy.resultContract === 'brainstem.c2d-result/v1' &&
            policy.resultProfile === 'brainstem.personal-resting-heart-overview/v1' &&
            policy.candidateManifestSha256 === null &&
            policy.approvedManifestSha256 === null &&
            policy.referenceSha256 === null
          : methods
            ? policy.maximumRecordings === 16 &&
              policy.algorithmVersion === '0.1.0' &&
              policy.inputSchema === 'brainstem.personal-resting-hrv-methods/v1' &&
              policy.inputPolicy ===
                'brainstem.personal-resting-hrv-methods/latest-16/v1' &&
              policy.resultContract === 'brainstem.insight-result/v1' &&
              policy.resultProfile === 'brainstem.resting-hrv-methods-personal/v1' &&
              policy.candidateManifestSha256 !== null &&
              policy.approvedManifestSha256 !== null &&
              policy.referenceSha256 !== null
            : sampleEntropy
              ? policy.maximumRecordings === 4 &&
                policy.algorithmVersion === '0.1.0' &&
                policy.inputSchema === 'brainstem.personal-resting-sample-entropy/v1' &&
                policy.inputPolicy ===
                  'brainstem.personal-resting-sample-entropy/latest-4/v1' &&
                policy.resultContract === 'brainstem.insight-result/v1' &&
                policy.resultProfile === 'brainstem.resting-sample-entropy-personal/v1' &&
                policy.candidateManifestSha256 ===
                  '65002ab13f02f812c611085c0295b81dc90ec7ffacc79f9ff4927e81e9070bdd' &&
                policy.approvedManifestSha256 !== null &&
                policy.referenceSha256 !== null
              : overnight
                ? policy.maximumRecordings === 9 &&
                  policy.algorithmVersion === '0.1.0' &&
                  policy.inputSchema ===
                    'brainstem.personal-overnight-heart-rate-change/v1' &&
                  policy.inputPolicy ===
                    'brainstem.personal-overnight-heart-rate-change/latest-distinct-9/v1' &&
                  policy.resultContract === 'brainstem.insight-result/v1' &&
                  policy.resultProfile ===
                    'brainstem.overnight-heart-rate-change-personal/v1' &&
                  policy.candidateManifestSha256 ===
                    '11accac777e72b9ee566531f174658d47fc211992223b5285f97fb7c003088f7' &&
                  policy.approvedManifestSha256 !== null &&
                  policy.referenceSha256 === null &&
                  policy.evidenceTier === 'E1_public_reproduced'
                : repeatability
                  ? policy.maximumRecordings === 7 &&
                    policy.algorithmVersion === '0.1.0' &&
                    policy.inputSchema ===
                      'brainstem.personal-resting-hrv-repeatability/v1' &&
                    policy.inputPolicy ===
                      'brainstem.personal-resting-hrv-repeatability/latest-distinct-7/v1' &&
                    policy.resultContract === 'brainstem.insight-result/v1' &&
                    policy.resultProfile ===
                      'brainstem.resting-hrv-repeatability-personal/v1' &&
                    policy.candidateManifestSha256 ===
                      '09e22348e350bb9e1da7183929675f7d67e718eb183075a7735c5513468905dd' &&
                    policy.approvedManifestSha256 !== null &&
                    policy.referenceSha256 === null &&
                    policy.evidenceTier === 'E0_candidate'
                  : guidedBreathing
                    ? policy.maximumRecordings === 7 &&
                      policy.algorithmVersion === '0.1.0' &&
                      policy.inputSchema ===
                        'brainstem.personal-guided-breathing-response/v1' &&
                      policy.inputPolicy ===
                        'brainstem.personal-guided-breathing-response/protocol-6-5-0-5-0/latest-7/v1' &&
                      policy.resultContract === 'brainstem.insight-result/v1' &&
                      policy.resultProfile ===
                        'brainstem.guided-breathing-response-personal/v1' &&
                      policy.candidateManifestSha256 ===
                        'e64490c6539db744350ee761db4a1fedffd6f9f631f8814480a684c1fdc4931d' &&
                      policy.approvedManifestSha256 !== null &&
                      policy.referenceSha256 ===
                        '45d96a1769a6cd8e51c74ff603bc4589427fb8bfc2b6f69e65c4037c1c1e6232' &&
                      policy.evidenceTier === 'E2_brainstem_compatible_exploratory'
                    : standing
                      ? policy.maximumRecordings === 7 &&
                        policy.algorithmVersion === '0.1.0' &&
                        policy.inputSchema ===
                          'brainstem.personal-standing-heart-rate-response/v1' &&
                        policy.inputPolicy ===
                          'brainstem.personal-standing-heart-rate-response/latest-7/v1' &&
                        policy.resultContract === 'brainstem.insight-result/v1' &&
                        policy.resultProfile ===
                          'brainstem.standing-heart-rate-response-personal/v1' &&
                        policy.candidateManifestSha256 ===
                          'ee503af519ed241f1f7ec965b58ad41b38c622c71a43e3f44c86743722ac4217' &&
                        policy.approvedManifestSha256 !== null &&
                        policy.referenceSha256 ===
                          'ffba0c6772fba94d5a18ec130cd5d0b080cb4f819d8c3fc4034a2b2dfd578979' &&
                        policy.evidenceTier === 'E2_brainstem_compatible_exploratory'
                      : policy.maximumRecordings === 7 &&
                        policy.algorithmVersion === '0.1.0' &&
                        policy.inputSchema === 'brainstem.personal-sleep-baseline/v1' &&
                        policy.inputPolicy ===
                          'brainstem.personal-sleep-baseline/latest-7/v1' &&
                        policy.resultContract === 'brainstem.insight-result/v1' &&
                        policy.resultProfile === 'brainstem.sleep-baseline-personal/v1' &&
                        policy.candidateManifestSha256 ===
                          '4c24414518539dd6ff2c1a166e6d588f01e3a3fa9572111fb15b6729c7c7300e' &&
                        policy.approvedManifestSha256 !== null &&
                        policy.referenceSha256 !== null
        if (!exactPolicy) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['analysisId'],
            message: 'Personal Insight policy fields do not match the named analysis'
          })
        }
        if (policy.bffBearerTokenEnv === policy.bearerTokenEnv) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['bffBearerTokenEnv'],
            message: 'Personal Insight BFF and Crab credentials must be separate'
          })
        }
        if (
          url.protocol !== 'https:' &&
          !(
            policy.allowInsecureLocalProof &&
            url.protocol === 'http:' &&
            isLocalProofHostname(url.hostname)
          )
        ) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['crabUrl'],
            message:
              'Personal Insight Crab URL requires HTTPS unless the explicit local-proof flag is set'
          })
        }
        if (policy.tls && url.protocol !== 'https:') {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['tls'],
            message: 'Personal Insight mTLS requires HTTPS'
          })
        }
      })
      .optional()
  })
  .refine(
    (data) =>
      data.personalInsight !== undefined ||
      (data.fees !== undefined && Object.keys(data.fees).length > 0) ||
      (data.free !== undefined && data.free !== null),
    {
      message:
        'Each environment must have either a non-empty "fees" configuration or a "free" configuration'
    }
  )
  .refine((data) => !(data.privateDataset && data.personalInsight), {
    message: 'Cohort private-dataset and personal-Insight policies are mutually exclusive'
  })
  .refine(
    (data) => {
      if (!data.privateDataset?.tls) return true
      const url = new URL(data.privateDataset.url)
      return (
        url.protocol === 'https:' &&
        url.hostname.toLowerCase() === data.privateDataset.tls.serverName.toLowerCase()
      )
    },
    {
      message: 'Private dataset mTLS requires HTTPS and a matching server name'
    }
  )
  .refine(
    (data) =>
      !data.personalInsight ||
      (data.enableNetwork === false &&
        data.consumerResultPolicy.mode === 'singleJson' &&
        data.consumerResultPolicy.resultContract ===
          data.personalInsight.resultContract &&
        data.consumerResultPolicy.maxBytes === data.personalInsight.maxResultBytes &&
        data.maxJobDuration === data.personalInsight.maxJobDuration &&
        !data.free),
    {
      message:
        'Personal Insight environments require fixed networkless execution, exact bounded result policy and duration, and no public free tier'
    }
  )
  .refine(
    (data) =>
      !data.personalInsight ||
      (data.resources?.length === 3 &&
        ['cpu', 'disk', 'ram'].every(
          (id) => data.resources?.filter((resource) => resource.id === id).length === 1
        )),
    {
      message:
        'Personal Insight environments require exactly one cpu, ram and disk resource'
    }
  )
  .refine(
    (data) =>
      !data.privateDataset ||
      (data.enableNetwork === false &&
        data.consumerResultPolicy.mode === 'singleJson' &&
        data.consumerResultPolicy.resultContract ===
          (data.privateDataset.paperInsight
            ? 'brainstem.insight-result/v1'
            : 'brainstem.c2d-result/v1') &&
        data.free?.allowImageBuild !== true),
    {
      message:
        'Private dataset environments require disabled algorithm networking, bounded contract-validated single-JSON results, and disabled image builds'
    }
  )
  .refine((data) => !data.privateDataset || data.storageExpiry === 14 * 24 * 60 * 60, {
    message: 'Private dataset aggregate results require exactly 14 days retention'
  })
  .refine((data) => !data.personalInsight || data.storageExpiry === 14 * 24 * 60 * 60, {
    message: 'Personal Insight results require exactly 14 days retention'
  })
  .refine((data) => data.storageExpiry >= data.maxJobDuration, {
    message: '"storageExpiry" should be greater than "maxJobDuration"'
  })
  .refine(
    (data) => {
      if (!data.resources) return false
      return data.resources.some((r) => r.id === 'disk' && r.total)
    },
    { message: 'There is no "disk" resource configured. This is mandatory' }
  )

const ImageScanSeveritySchema = z.enum(['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])

export const C2DDockerConfigSchema = z.array(
  z
    .object({
      socketPath: z.string().optional(),
      protocol: z.string().optional(),
      host: z.string().optional(),
      port: z.number().optional(),
      caPath: z.string().optional(),
      certPath: z.string().optional(),
      keyPath: z.string().optional(),
      imageRetentionDays: z.number().int().min(1).optional().default(7),
      imageCleanupInterval: z.number().int().min(3600).optional().default(86400), // min 1 hour, default 24 hours
      paymentClaimInterval: z.number().int().min(1).optional().default(3600),
      scanImages: z.boolean().optional().default(false),
      scanImageRejectSeverities: z.array(ImageScanSeveritySchema).optional(),
      scanImageDBUpdateInterval: z.number().int().min(3600).optional().default(43200), // default 43200 (12 hours)
      environments: z.array(C2DEnvironmentConfigSchema).min(1)
    })
    .superRefine((data, context) => {
      if (data.scanImages && !data.scanImageRejectSeverities?.length) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['scanImageRejectSeverities'],
          message:
            'scanImageRejectSeverities must be a non-empty list when scanImages is true'
        })
      }
      if (
        data.environments.some((environment) => environment.personalInsight) &&
        (!data.scanImages || !data.scanImageRejectSeverities?.length)
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['scanImages'],
          message: 'Personal Insight environments require fail-closed image scanning'
        })
      }
    })
)

export const C2DClusterInfoSchema = z.object({
  type: z.nativeEnum(C2DClusterType),
  hash: z.string(),
  connection: z.any().optional(),
  tempFolder: z.string().optional()
})

export const OceanNodeP2PConfigSchema = z.object({
  bootstrapNodes: jsonFromString(z.array(z.string())).default([
    ...DEFAULT_BOOTSTRAP_ADDRESSES
  ]),
  bootstrapTimeout: z.coerce.number().optional().default(10000),
  bootstrapTagName: z.string().optional().default('bootstrap'),
  bootstrapTagValue: z.coerce.number().optional().default(50),
  bootstrapTTL: z.coerce.number().optional(),
  enableIPV4: booleanFromString.optional().default(true),
  enableIPV6: booleanFromString.optional().default(true),
  ipV4BindAddress: z.string().nullable().optional().default('0.0.0.0'),
  ipV4BindTcpPort: z.coerce.number().nullable().optional().default(9000),
  ipV4BindWsPort: z.coerce.number().nullable().optional().default(9001),
  ipV4BindWssPort: z.coerce.number().nullable().optional().default(9005),
  ipV6BindAddress: z.string().nullable().optional().default('::'),
  ipV6BindTcpPort: z.coerce.number().nullable().optional().default(9002),
  ipV6BindWsPort: z.coerce.number().nullable().optional().default(9003),
  pubsubPeerDiscoveryInterval: z.coerce.number().optional().default(1000),
  dhtMaxInboundStreams: z.coerce.number().optional().default(500),
  dhtMaxOutboundStreams: z.coerce.number().optional().default(500),
  dhtFilter: z
    .union([z.nativeEnum(dhtFilterMethod), z.string(), z.number(), z.null()])
    .transform((v) => {
      if (v === null) {
        return dhtFilterMethod.filterNone
      }
      if (typeof v === 'number' || typeof v === 'string') {
        const filterValue = typeof v === 'string' ? parseInt(v, 10) : v
        switch (filterValue) {
          case 1:
            return dhtFilterMethod.filterPrivate
          case 2:
            return dhtFilterMethod.filterPublic
          default:
            return dhtFilterMethod.filterNone
        }
      }
      return v
    })
    .optional()
    .default(dhtFilterMethod.filterNone),
  mDNSInterval: z.coerce.number().optional().default(20e3),
  connectionsMaxParallelDials: z.coerce.number().optional().default(15),
  connectionsDialTimeout: z.coerce.number().optional().default(30e3),
  upnp: booleanFromString.optional().default(true),
  autoNat: booleanFromString.optional().default(true),
  enableCircuitRelayServer: booleanFromString.optional().default(false),
  enableCircuitRelayClient: booleanFromString.optional().default(false),
  circuitRelays: z.coerce.number().optional().default(0),
  announcePrivateIp: booleanFromString.optional().default(false),
  announceAddresses: jsonFromString(z.array(z.string())).optional().default([]),
  filterAnnouncedAddresses: jsonFromString(z.array(z.string()))
    .optional()
    .default([...DEFAULT_FILTER_ANNOUNCED_ADDRESSES]),
  minConnections: z.coerce.number().optional().default(1),
  maxConnections: z.coerce.number().optional().default(300),
  autoDialPeerRetryThreshold: z.coerce.number().optional().default(120000),
  autoDialConcurrency: z.coerce.number().optional().default(5),
  maxPeerAddrsToDial: z.coerce.number().optional().default(5),
  autoDialInterval: z.coerce.number().optional().default(5000),
  enableNetworkStats: booleanFromString.optional().default(false)
})

const addressArrayFromString = jsonFromString(z.array(z.string())).transform(
  (addresses) => {
    if (!Array.isArray(addresses)) return []
    try {
      return addresses.map((addr) => getAddress(addr))
    } catch (error) {
      CONFIG_LOGGER.error(`Invalid address in list: ${error.message}`)
      return []
    }
  }
)

export const OceanNodeConfigSchema = z
  .object({
    dockerComputeEnvironments: jsonFromString(C2DDockerConfigSchema)
      .optional()
      .default([]),

    dockerRegistrysAuth: jsonFromString(DockerRegistrysSchema).optional().default({}),

    authorizedDecrypters: addressArrayFromString.optional().default([]),
    authorizedDecryptersList: jsonFromString(AccessListContractSchema).optional(),

    allowedValidators: addressArrayFromString.optional().default([]),
    allowedValidatorsList: jsonFromString(AccessListContractSchema).optional(),

    authorizedPublishers: addressArrayFromString.optional().default([]),
    authorizedPublishersList: jsonFromString(AccessListContractSchema).optional(),

    keys: OceanNodeConfigKeysSchema.optional(),

    INTERFACES: z.string().optional(),
    hasP2P: booleanFromString.optional().default(true),
    hasHttp: booleanFromString.optional().default(true),
    enableBenchmark: booleanFromString.optional().default(false),

    p2pConfig: OceanNodeP2PConfigSchema.nullable().optional(),
    hasIndexer: booleanFromString.default(true),

    DB_URL: z.string().optional(),
    DB_USERNAME: z.string().optional(),
    DB_PASSWORD: z.string().optional(),
    DB_TYPE: z.string().optional(),
    dbConfig: OceanNodeDBConfigSchema.optional(),
    // Accept either an object (config file) or a JSON string (env var `PERSISTENT_STORAGE`),
    // and validate the parsed value against the PersistentStorage schema.
    persistentStorage: z
      .preprocess((val) => {
        if (val === undefined || val === null) return val
        if (typeof val === 'string') {
          const tryParse = (s: string) => {
            try {
              return JSON.parse(s)
            } catch {
              return undefined
            }
          }

          // 1) Normal JSON string
          const parsed = tryParse(val)
          if (parsed !== undefined) {
            // 2) Handle double-encoded JSON (e.g. "\"{...}\"")
            if (typeof parsed === 'string') {
              const parsedTwice = tryParse(parsed)
              if (parsedTwice !== undefined) return parsedTwice
            }
            return parsed
          }

          // 3) Common docker-compose/shell mistake: single quotes inside JSON
          const normalized = val.replace(/'/g, '"')
          const parsedNormalized = tryParse(normalized)
          if (parsedNormalized !== undefined) return parsedNormalized

          return val
        }
        return val
      }, PersistentStorageConfigSchema)
      .optional(),

    FEE_AMOUNT: z.string().optional(),
    FEE_TOKENS: z.string().optional(),
    feeStrategy: FeeStrategySchema.optional(),
    skipFeeTokenValidation: booleanFromString.optional().default(false),

    httpPort: z.coerce.number().optional().default(3000),
    rateLimit: z.coerce.number().optional().default(DEFAULT_RATE_LIMIT_PER_MINUTE),

    ipfsGateway: z.string().nullable().optional(),
    arweaveGateway: z.string().nullable().optional(),

    supportedNetworks: jsonFromString(RPCSSchema).optional(),

    claimDurationTimeout: z.coerce.number().default(3600),
    indexingNetworks: z
      .union([jsonFromString(RPCSSchema), z.array(z.union([z.string(), z.number()]))])
      .optional(),

    c2dClusters: z.array(C2DClusterInfoSchema).optional(),
    accountPurgatoryUrl: z
      .string()
      .nullable()
      .refine((url) => !url || isValidUrl(url), {
        message: 'accountPurgatoryUrl must be a valid URL'
      }),
    assetPurgatoryUrl: z
      .string()
      .nullable()
      .refine((url) => !url || isValidUrl(url), {
        message: 'assetPurgatoryUrl must be a valid URL'
      }),
    allowedAdmins: addressArrayFromString.optional(),
    allowedAdminsList: jsonFromString(AccessListContractSchema).optional(),

    codeHash: z.string().optional(),
    maxConnections: z.coerce.number().optional(),
    denyList: jsonFromString(DenyListSchema).optional().default({ peers: [], ips: [] }),
    unsafeURLs: jsonFromString(z.array(z.string()))
      .optional()
      .default([...DEFAULT_UNSAFE_URLS]),
    isBootstrap: booleanFromString.optional().default(false),
    validateUnsignedDDO: booleanFromString.optional().default(true),
    jwtSecret: z.string(),
    httpCertPath: z.string().optional(),
    httpKeyPath: z.string().optional()
  })
  .passthrough()
  .superRefine((data, ctx) => {
    if (!data.hasHttp && !data.hasP2P) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'At least one interface (HTTP or P2P) must be enabled',
        path: ['hasHttp']
      })
    }

    if (data.hasP2P && !data.p2pConfig) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'P2P configuration is required when hasP2P is true',
        path: ['p2pConfig']
      })
    }
  })

export type OceanNodeConfigParsed = z.infer<typeof OceanNodeConfigSchema>
