import { expect } from 'chai'
import { OceanNodeConfig } from '../../@types/OceanNode.js'
import { getConfiguration, loadConfigFromFile } from '../../utils/config.js'
import {
  OverrideEnvConfig,
  TEST_ENV_CONFIG_PATH,
  buildEnvOverrideConfig,
  setupEnvironment
} from '../utils/utils.js'
import { ENVIRONMENT_VARIABLES } from '../../utils/constants.js'
import {
  C2DDockerConfigSchema,
  C2DEnvironmentConfigSchema
} from '../../utils/config/schemas.js'
import {
  createComputeEnvironmentId,
  TRIVY_IMAGE
} from '../../components/c2d/compute_engine_docker.js'

let config: OceanNodeConfig
describe('Should validate configuration from JSON', () => {
  let envOverrides: OverrideEnvConfig[]
  before(async () => {
    envOverrides = buildEnvOverrideConfig(
      [ENVIRONMENT_VARIABLES.DB_TYPE, ENVIRONMENT_VARIABLES.DB_URL],
      ['typesense', 'http://localhost:8108/?apiKey=xyz']
    )
    envOverrides = await setupEnvironment(TEST_ENV_CONFIG_PATH, envOverrides)
    config = await getConfiguration(true)
  })

  it('should get indexer networks from config', () => {
    expect(Object.keys(config.indexingNetworks).length).to.be.equal(1)
    expect(config.indexingNetworks['8996']).to.not.equal(undefined)
    expect(config.indexingNetworks['8996'].chainId).to.be.equal(8996)
    expect(config.indexingNetworks['8996'].rpc).to.be.equal('http://127.0.0.1:8545')
    expect(config.indexingNetworks['8996'].network).to.be.equal('development')
    expect(config.indexingNetworks['8996'].chunkSize).to.be.equal(100)
  })

  it('should have indexer', () => {
    expect(config.hasIndexer).to.be.equal(true)
    expect(config.dbConfig).to.not.be.equal(null)
    // it is exported in the env vars, so it should overwrite the config.json
    expect(config.dbConfig.dbType).to.be.equal('typesense')
    const configFile = loadConfigFromFile(process.env.CONFIG_PATH)
    expect(config.dbConfig.dbType).to.not.be.equal(configFile.dbConfig.dbType)
    expect(config.dbConfig.url).to.be.equal('http://localhost:8108/?apiKey=xyz')
  })

  it('should have HTTP', () => {
    expect(config.hasHttp).to.be.equal(true)
    expect(config.httpPort).to.be.equal(8001)
  })

  it('should have P2P', () => {
    expect(config.hasP2P).to.be.equal(true)
    expect(config.p2pConfig).to.not.be.equal(null)
    expect(config.p2pConfig.bootstrapNodes).to.not.be.equal(null)
    expect(config.p2pConfig.bootstrapNodes.length).to.be.equal(0)
  })
  it('should have defaults set', () => {
    expect(config.isBootstrap).to.be.equal(false)
    expect(config.validateUnsignedDDO).to.be.equal(true)
  })
  after(() => {
    delete process.env.CONFIG_PATH
    delete process.env.PRIVATE_KEY
  })
})

describe('Should require an explicit consumer result policy', () => {
  const baseEnvironment = {
    resources: [{ id: 'disk', total: 1 }],
    free: { resources: [{ id: 'disk', max: 1 }] }
  }

  it('rejects an environment with no result policy', () => {
    expect(C2DEnvironmentConfigSchema.safeParse(baseEnvironment).success).to.equal(false)
  })

  it('accepts explicit archive and bounded single JSON policies', () => {
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        consumerResultPolicy: { mode: 'archive' }
      }).success
    ).to.equal(true)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        consumerResultPolicy: { mode: 'singleJson', maxBytes: 262144 }
      }).success
    ).to.equal(true)
  })

  it('changes the environment identity when only the result policy changes', () => {
    const archive = createComputeEnvironmentId('cluster', null, { mode: 'archive' }, '0')
    const strict = createComputeEnvironmentId(
      'cluster',
      null,
      { mode: 'singleJson', maxBytes: 262144 },
      '0'
    )

    expect(strict).not.to.equal(archive)
  })

  it('rejects unbounded and oversized single JSON policies', () => {
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        consumerResultPolicy: { mode: 'singleJson' }
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        consumerResultPolicy: { mode: 'singleJson', maxBytes: 10 * 1024 * 1024 + 1 }
      }).success
    ).to.equal(false)
  })

  it('validates and identity-binds a private dataset policy', () => {
    const privateDataset = {
      analysisId: 'brainstem.resting-rr-cohort-summary/v1' as const,
      url: 'http://crab:8080/api/v1/internal/c2d/rr-cohort',
      maxBytes: 16 * 1024 * 1024,
      approvedAlgorithmImage: `brainstem/private-rr@sha256:${'a'.repeat(64)}`,
      bearerTokenEnv: 'CRAB_C2D_BEARER_TOKEN',
      releaseId: 'b'.repeat(64),
      allowInsecureLocalProof: true,
      participantValue: {
        crabSignerAddress: '0x1111111111111111111111111111111111111111'
      }
    }
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        storageExpiry: 14 * 24 * 60 * 60,
        consumerResultPolicy: {
          mode: 'singleJson',
          maxBytes: 262144,
          resultContract: 'brainstem.c2d-result/v1'
        },
        privateDataset
      }).success
    ).to.equal(true)
    const reviewedStudy = {
      ...privateDataset,
      analysisId: 'brainstem.full-night-rr-signal-compatibility/v1',
      participantValue: undefined as undefined,
      study: {
        proposalId: 'study_a',
        revisionId: 'revision_b',
        revisionSha256: 'c'.repeat(64),
        dataPermitId: `data_permit_${'d'.repeat(32)}`,
        resultBearerTokenEnv: 'STUDY_RESULT_NODE_TOKEN'
      }
    }
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        storageExpiry: 14 * 24 * 60 * 60,
        consumerResultPolicy: {
          mode: 'singleJson',
          maxBytes: 262144,
          resultContract: 'brainstem.c2d-result/v1'
        },
        privateDataset: reviewedStudy
      }).success
    ).to.equal(true)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        storageExpiry: 14 * 24 * 60 * 60,
        consumerResultPolicy: {
          mode: 'singleJson',
          maxBytes: 262145,
          resultContract: 'brainstem.c2d-result/v1'
        },
        privateDataset: reviewedStudy
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        storageExpiry: 14 * 24 * 60 * 60,
        consumerResultPolicy: {
          mode: 'singleJson',
          maxBytes: 262144,
          resultContract: 'brainstem.c2d-result/v1'
        },
        privateDataset: { ...reviewedStudy, study: undefined }
      }).success
    ).to.equal(false)
    const reviewedMethods = {
      ...privateDataset,
      analysisId: 'brainstem.resting-hrv-methods/v1',
      participantValue: undefined as undefined,
      paperInsight: {
        algorithmVersion: '0.1.0',
        inputSchema: 'brainstem.resting-hrv-methods-cohort/v1',
        candidateManifestSha256:
          '15dbf8544c87d81c06f5e512b00e9fe39dd6431dd1a4079a97da68a3f92721c1',
        approvedManifestSha256: 'c'.repeat(64),
        referenceSha256: 'd'.repeat(64),
        evidenceTier: 'E2_brainstem_compatible_exploratory',
        useClass: 'methods_only',
        clinicalUse: 'prohibited'
      }
    }
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        storageExpiry: 14 * 24 * 60 * 60,
        consumerResultPolicy: {
          mode: 'singleJson',
          maxBytes: 262144,
          resultContract: 'brainstem.insight-result/v1'
        },
        privateDataset: reviewedMethods
      }).success
    ).to.equal(true)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        storageExpiry: 14 * 24 * 60 * 60,
        consumerResultPolicy: {
          mode: 'singleJson',
          maxBytes: 262144,
          resultContract: 'brainstem.insight-result/v1'
        },
        privateDataset: { ...reviewedMethods, study: reviewedStudy.study }
      }).success
    ).to.equal(false)
    const sampleEntropy = {
      ...reviewedMethods,
      analysisId: 'brainstem.resting-rr-sample-entropy/v1',
      paperInsight: {
        ...reviewedMethods.paperInsight,
        inputSchema: 'brainstem.resting-sample-entropy-cohort/v1',
        candidateManifestSha256:
          '65002ab13f02f812c611085c0295b81dc90ec7ffacc79f9ff4927e81e9070bdd'
      }
    }
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        storageExpiry: 14 * 24 * 60 * 60,
        consumerResultPolicy: {
          mode: 'singleJson',
          maxBytes: 262144,
          resultContract: 'brainstem.insight-result/v1'
        },
        privateDataset: sampleEntropy
      }).success
    ).to.equal(true)
    const sleepReliability = {
      ...reviewedMethods,
      analysisId: 'brainstem.sleep-reliability-benchmark/v1',
      paperInsight: {
        ...reviewedMethods.paperInsight,
        algorithmVersion: '0.3.0',
        inputSchema: 'brainstem.sleep-nightly-features-cohort/v1',
        candidateManifestSha256:
          'b9bcc30891ffa7368f6169947b9aea9e2bb968a4a4db56287bd1ffde98d94073',
        referenceSha256: null as null,
        evidenceTier: 'E0_candidate'
      }
    }
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        storageExpiry: 14 * 24 * 60 * 60,
        consumerResultPolicy: {
          mode: 'singleJson',
          maxBytes: 262144,
          resultContract: 'brainstem.c2d-result/v1'
        },
        privateDataset: sleepReliability
      }).success
    ).to.equal(true)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        storageExpiry: 14 * 24 * 60 * 60,
        consumerResultPolicy: {
          mode: 'singleJson',
          maxBytes: 262144,
          resultContract: 'brainstem.c2d-result/v1'
        },
        privateDataset: {
          ...sleepReliability,
          paperInsight: {
            ...sleepReliability.paperInsight,
            algorithmVersion: '0.2.0'
          }
        }
      }).success
    ).to.equal(false)
    const standingResponse = {
      ...reviewedMethods,
      analysisId: 'brainstem.standing-heart-rate-response/v1',
      paperInsight: {
        ...reviewedMethods.paperInsight,
        inputSchema: 'brainstem.standing-heart-rate-response-cohort/v1',
        candidateManifestSha256:
          'ee503af519ed241f1f7ec965b58ad41b38c622c71a43e3f44c86743722ac4217',
        referenceSha256: null as null,
        evidenceTier: 'E2_brainstem_compatible_exploratory'
      }
    }
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        storageExpiry: 14 * 24 * 60 * 60,
        consumerResultPolicy: {
          mode: 'singleJson',
          maxBytes: 262144,
          resultContract: 'brainstem.insight-result/v1'
        },
        privateDataset: standingResponse
      }).success
    ).to.equal(true)
    const guidedBreathing = {
      ...reviewedMethods,
      analysisId: 'brainstem.guided-breathing-response/v1',
      paperInsight: {
        ...reviewedMethods.paperInsight,
        inputSchema: 'brainstem.guided-breathing-response-cohort/v1',
        candidateManifestSha256:
          'e64490c6539db744350ee761db4a1fedffd6f9f631f8814480a684c1fdc4931d',
        referenceSha256: null as null,
        evidenceTier: 'E2_brainstem_compatible_exploratory'
      }
    }
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        storageExpiry: 14 * 24 * 60 * 60,
        consumerResultPolicy: {
          mode: 'singleJson',
          maxBytes: 262144,
          resultContract: 'brainstem.insight-result/v1'
        },
        privateDataset: guidedBreathing
      }).success
    ).to.equal(true)
    const standingResponseV2 = {
      ...standingResponse,
      analysisId: 'brainstem.standing-heart-rate-response/v2',
      study: reviewedStudy.study,
      paperInsight: {
        ...standingResponse.paperInsight,
        algorithmVersion: '0.2.0',
        inputSchema: 'brainstem.standing-heart-rate-response-cohort/v2',
        candidateManifestSha256:
          '9dd1ff3e4ff551b128f44f61fdf33799f1e7514af5cd505eeae4b2db67a496fa',
        approvedManifestSha256:
          '7351da697fed84e68afbc440aef1d43f1de834363a862b8d912fa831f13e61b0',
        referenceSha256:
          '188183a7b0ac8c046d1139219f252ed37142505107ee94d69472bf43105eb3cb'
      }
    }
    const v2Environment = {
      ...baseEnvironment,
      storageExpiry: 14 * 24 * 60 * 60,
      consumerResultPolicy: {
        mode: 'singleJson',
        maxBytes: 262144,
        resultContract: 'brainstem.insight-result/v1'
      },
      privateDataset: standingResponseV2
    }
    expect(C2DEnvironmentConfigSchema.safeParse(v2Environment).success).to.equal(true)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...v2Environment,
        privateDataset: { ...standingResponseV2, study: undefined }
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...v2Environment,
        privateDataset: {
          ...standingResponseV2,
          paperInsight: {
            ...standingResponseV2.paperInsight,
            approvedManifestSha256: '0'.repeat(64)
          }
        }
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        storageExpiry: 14 * 24 * 60 * 60,
        consumerResultPolicy: {
          mode: 'singleJson',
          maxBytes: 262144,
          resultContract: 'brainstem.c2d-result/v1'
        },
        privateDataset: reviewedMethods
      }).success
    ).to.equal(false)

    const withoutPolicy = createComputeEnvironmentId(
      'cluster',
      null,
      { mode: 'singleJson', maxBytes: 262144 },
      '0'
    )
    const withPolicy = createComputeEnvironmentId(
      'cluster',
      null,
      {
        mode: 'singleJson',
        maxBytes: 262144,
        resultContract: 'brainstem.c2d-result/v1'
      },
      '0',
      privateDataset
    )
    expect(withPolicy).not.to.equal(withoutPolicy)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        storageExpiry: 7 * 24 * 60 * 60,
        consumerResultPolicy: {
          mode: 'singleJson',
          maxBytes: 262144,
          resultContract: 'brainstem.c2d-result/v1'
        },
        privateDataset
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        consumerResultPolicy: { mode: 'singleJson', maxBytes: 262144 },
        privateDataset
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        storageExpiry: 14 * 24 * 60 * 60,
        consumerResultPolicy: {
          mode: 'singleJson',
          maxBytes: 262144,
          resultContract: 'brainstem.c2d-result/v1'
        },
        privateDataset: {
          ...privateDataset,
          participantValue: { crabSignerAddress: 'not-an-address' }
        }
      }).success
    ).to.equal(false)
  })

  it('rejects unbounded or mutable private dataset policies', () => {
    const policy = {
      analysisId: 'brainstem.resting-rr-cohort-summary/v1' as const,
      url: 'http://crab:8080/api/v1/internal/c2d/rr-cohort',
      maxBytes: 16 * 1024 * 1024,
      approvedAlgorithmImage: `brainstem/private-rr@sha256:${'a'.repeat(64)}`,
      bearerTokenEnv: 'CRAB_C2D_BEARER_TOKEN',
      releaseId: 'b'.repeat(64),
      allowInsecureLocalProof: true
    }
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        consumerResultPolicy: { mode: 'archive' },
        privateDataset: { ...policy, maxBytes: 16 * 1024 * 1024 + 1 }
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        consumerResultPolicy: { mode: 'archive' },
        privateDataset: {
          ...policy,
          approvedAlgorithmImage: 'brainstem/private-rr:latest'
        }
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        consumerResultPolicy: { mode: 'archive' },
        privateDataset: {
          ...policy,
          url: `${policy.url}?serviceToken=must-not-live-in-the-url`
        }
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        consumerResultPolicy: { mode: 'archive' },
        privateDataset: { ...policy, bearerTokenEnv: 'not a safe env name' }
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...baseEnvironment,
        privateDataset: { ...policy, releaseId: 'named-release' }
      }).success
    ).to.equal(false)
  })

  it('requires a bounded secret mount and matching HTTPS identity for mTLS', () => {
    const policy = {
      analysisId: 'brainstem.resting-rr-cohort-summary/v1' as const,
      url: 'https://crab-export.internal/api/v1/internal/c2d/rr-cohort',
      maxBytes: 16 * 1024 * 1024,
      approvedAlgorithmImage: `brainstem/private-rr@sha256:${'a'.repeat(64)}`,
      bearerTokenEnv: 'CRAB_C2D_BEARER_TOKEN',
      releaseId: 'b'.repeat(64),
      tls: {
        caFile: '/run/brainstem-secrets/crab-ca.pem',
        clientCertificateFile: '/run/brainstem-secrets/ocean-client.pem',
        clientKeyFile: '/run/brainstem-secrets/ocean-client-key.pem',
        serverName: 'crab-export.internal'
      }
    }
    const environment = {
      ...baseEnvironment,
      storageExpiry: 14 * 24 * 60 * 60,
      consumerResultPolicy: {
        mode: 'singleJson',
        maxBytes: 262144,
        resultContract: 'brainstem.c2d-result/v1'
      }
    }

    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...environment,
        privateDataset: policy
      }).success
    ).to.equal(true)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...environment,
        privateDataset: {
          ...policy,
          url: 'http://crab-export.internal/api/v1/internal/c2d/rr-cohort'
        }
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...environment,
        privateDataset: {
          ...policy,
          tls: { ...policy.tls, serverName: 'other.internal' }
        }
      }).success
    ).to.equal(false)
    expect(
      C2DEnvironmentConfigSchema.safeParse({
        ...environment,
        privateDataset: {
          ...policy,
          tls: { ...policy.tls, clientKeyFile: '/tmp/client-key.pem' }
        }
      }).success
    ).to.equal(false)
  })

  it('rejects private datasets in exfiltration-prone environments', () => {
    const privateDataset = {
      analysisId: 'brainstem.resting-rr-cohort-summary/v1' as const,
      url: 'http://crab:8080/api/v1/internal/c2d/rr-cohort',
      maxBytes: 1024,
      approvedAlgorithmImage: `brainstem/private-rr@sha256:${'a'.repeat(64)}`,
      bearerTokenEnv: 'CRAB_C2D_BEARER_TOKEN',
      releaseId: 'b'.repeat(64)
    }
    for (const unsafe of [
      {
        enableNetwork: true,
        consumerResultPolicy: { mode: 'singleJson', maxBytes: 1024 }
      },
      { enableNetwork: false, consumerResultPolicy: { mode: 'archive' } },
      {
        enableNetwork: false,
        consumerResultPolicy: { mode: 'singleJson', maxBytes: 1024 },
        free: {
          resources: [{ id: 'disk', max: 1 }],
          allowImageBuild: true
        }
      }
    ]) {
      expect(
        C2DEnvironmentConfigSchema.safeParse({
          ...baseEnvironment,
          ...unsafe,
          privateDataset
        }).success
      ).to.equal(false)
    }
  })
})

describe('Should require an explicit image scan severity policy', () => {
  const environment = {
    consumerResultPolicy: { mode: 'archive' },
    resources: [{ id: 'disk', total: 1 }],
    free: { resources: [{ id: 'disk', max: 1 }] }
  }

  it('pins the scanner itself by immutable digest', () => {
    expect(TRIVY_IMAGE).to.match(/^aquasec\/trivy:[0-9.]+@sha256:[0-9a-f]{64}$/)
  })

  it('allows disabled scanning without a severity policy', () => {
    expect(
      C2DDockerConfigSchema.safeParse([
        { scanImages: false, environments: [environment] }
      ]).success
    ).to.equal(true)
  })

  it('requires a supported non-empty policy when scanning is enabled', () => {
    expect(
      C2DDockerConfigSchema.safeParse([{ scanImages: true, environments: [environment] }])
        .success
    ).to.equal(false)
    expect(
      C2DDockerConfigSchema.safeParse([
        {
          scanImages: true,
          scanImageRejectSeverities: ['HIGH', 'CRITICAL'],
          environments: [environment]
        }
      ]).success
    ).to.equal(true)
    expect(
      C2DDockerConfigSchema.safeParse([
        {
          scanImages: true,
          scanImageRejectSeverities: ['SEVERE'],
          environments: [environment]
        }
      ]).success
    ).to.equal(false)
  })
})

describe('Should retain a bounded settlement interval', () => {
  const environment = {
    consumerResultPolicy: { mode: 'archive' },
    resources: [{ id: 'disk', total: 1 }],
    free: { resources: [{ id: 'disk', max: 1 }] }
  }

  it('keeps an explicit interval and applies a safe default', () => {
    const explicit = C2DDockerConfigSchema.parse([
      { paymentClaimInterval: 2, environments: [environment] }
    ])
    expect(explicit[0].paymentClaimInterval).to.equal(2)
    const defaulted = C2DDockerConfigSchema.parse([{ environments: [environment] }])
    expect(defaulted[0].paymentClaimInterval).to.equal(3600)
    expect(
      C2DDockerConfigSchema.safeParse([
        { paymentClaimInterval: 0, environments: [environment] }
      ]).success
    ).to.equal(false)
  })
})

describe('Should validate P2P config from environment variables', () => {
  let config: OceanNodeConfig
  let envOverrides: OverrideEnvConfig[]

  before(async () => {
    envOverrides = buildEnvOverrideConfig(
      [
        ENVIRONMENT_VARIABLES.DB_TYPE,
        ENVIRONMENT_VARIABLES.DB_URL,
        ENVIRONMENT_VARIABLES.P2P_ipV4BindAddress,
        ENVIRONMENT_VARIABLES.P2P_ipV4BindTcpPort,
        ENVIRONMENT_VARIABLES.P2P_ipV6BindAddress,
        ENVIRONMENT_VARIABLES.P2P_MIN_CONNECTIONS,
        ENVIRONMENT_VARIABLES.P2P_MAX_CONNECTIONS
      ],
      [
        'typesense',
        'http://localhost:8108/?apiKey=xyz',
        '127.0.0.1',
        '9999',
        '::2',
        '5',
        '500'
      ]
    )
    envOverrides = await setupEnvironment(TEST_ENV_CONFIG_PATH, envOverrides)
    config = await getConfiguration(true)
  })

  it('should override P2P config values from environment variables', () => {
    expect(config.p2pConfig).to.not.be.equal(null)
    expect(config.p2pConfig.ipV4BindAddress).to.be.equal('127.0.0.1')
    expect(config.p2pConfig.ipV4BindTcpPort).to.be.equal(9999)
    expect(config.p2pConfig.ipV6BindAddress).to.be.equal('::2')
    expect(config.p2pConfig.minConnections).to.be.equal(5)
    expect(config.p2pConfig.maxConnections).to.be.equal(500)
  })

  it('should maintain non-overridden P2P config values from config.json', () => {
    expect(config.p2pConfig.enableIPV4).to.be.equal(true)
    expect(config.p2pConfig.enableIPV6).to.be.equal(true)
    expect(config.p2pConfig.upnp).to.be.equal(true)
    expect(config.p2pConfig.autoNat).to.be.equal(true)
    expect(config.p2pConfig.bootstrapNodes).to.not.be.equal(null)
  })

  after(() => {
    delete process.env.CONFIG_PATH
    delete process.env.PRIVATE_KEY
    delete process.env[ENVIRONMENT_VARIABLES.P2P_ipV4BindAddress.name]
    delete process.env[ENVIRONMENT_VARIABLES.P2P_ipV4BindTcpPort.name]
    delete process.env[ENVIRONMENT_VARIABLES.P2P_ipV6BindAddress.name]
    delete process.env[ENVIRONMENT_VARIABLES.P2P_MIN_CONNECTIONS.name]
    delete process.env[ENVIRONMENT_VARIABLES.P2P_MAX_CONNECTIONS.name]
  })
})
