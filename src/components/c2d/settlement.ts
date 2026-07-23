import {
  C2DStatusNumber,
  type ComputeSettlement,
  type DBComputeJob,
  type DBSettlementIntent
} from '../../@types/C2D/C2D.js'

export const SETTLEMENT_JOB_STATUSES = [
  C2DStatusNumber.JobQueuedExpired,
  C2DStatusNumber.PullImageFailed,
  C2DStatusNumber.BuildImageFailed,
  C2DStatusNumber.VulnerableImage,
  C2DStatusNumber.ImageScanFailed,
  C2DStatusNumber.VolumeCreationFailed,
  C2DStatusNumber.ContainerCreationFailed,
  C2DStatusNumber.DataProvisioningFailed,
  C2DStatusNumber.AlgorithmProvisioningFailed,
  C2DStatusNumber.DataUploadFailed,
  C2DStatusNumber.AlgorithmFailed,
  C2DStatusNumber.DiskQuotaExceeded,
  C2DStatusNumber.ResultsFetchFailed,
  C2DStatusNumber.ResultsUploadFailed,
  C2DStatusNumber.JobSettle
]

export type SettlementDecision = {
  decision: 'charge' | 'release'
  amount: number
  reason: string
}

export function decideSettlement(
  job: DBComputeJob,
  calculatedCost: number,
  requireValidatedResult: boolean
): SettlementDecision {
  if (job.status !== C2DStatusNumber.JobSettle) {
    return {
      decision: 'release',
      amount: 0,
      reason: `technical_failure:${job.status}`
    }
  }

  if (requireValidatedResult) {
    if (!job.resultValidation) {
      return { decision: 'release', amount: 0, reason: 'result_contract_missing' }
    }
    if (!job.resultValidation.billable) {
      return {
        decision: 'release',
        amount: 0,
        reason: `result_status:${job.resultValidation.status}`
      }
    }
  }

  return {
    decision: 'charge',
    amount: calculatedCost,
    reason: job.stopRequested
      ? 'validated_result_after_consumer_stop'
      : job.resultValidation?.status === 'insufficient_data'
        ? 'validated_privacy_suppression'
        : 'validated_result'
  }
}

export function sameSettlementIntent(
  existing: DBSettlementIntent,
  expected: DBSettlementIntent
): boolean {
  return (
    existing.settlementKey === expected.settlementKey &&
    existing.jobId === expected.jobId &&
    existing.jobIdHash === expected.jobIdHash &&
    existing.chainId === expected.chainId &&
    existing.escrowAddress.toLowerCase() === expected.escrowAddress.toLowerCase() &&
    existing.token.toLowerCase() === expected.token.toLowerCase() &&
    existing.payer.toLowerCase() === expected.payer.toLowerCase() &&
    existing.decision === expected.decision &&
    existing.amount === expected.amount &&
    existing.reason === expected.reason &&
    existing.transactionHash === expected.transactionHash &&
    existing.rawTransaction === expected.rawTransaction
  )
}

export function projectSettlement(
  intent: DBSettlementIntent | null
): ComputeSettlement | undefined {
  if (!intent) return undefined

  if (
    !['charged', 'not_charged', 'refunded', 'refund_required'].includes(intent.status)
  ) {
    return { status: 'unknown', amount: 0 }
  }
  return {
    status: intent.status as ComputeSettlement['status'],
    amount: intent.status === 'not_charged' ? 0 : (intent.settledAmount ?? intent.amount),
    chainId: intent.chainId,
    token: intent.token,
    transactionHash: intent.transactionHash
  }
}
