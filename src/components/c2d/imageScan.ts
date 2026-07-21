import type { ImageScanSeverity } from '../../@types/C2D/C2D.js'

export const IMAGE_SCAN_SEVERITIES: ImageScanSeverity[] = [
  'UNKNOWN',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL'
]

export type ImageScanSummary = {
  total: number
  bySeverity: Record<ImageScanSeverity, number>
  list: Array<{
    severity: ImageScanSeverity
    id: string
    package: string
    title: string
  }>
}

export function evaluateTrivyReport(
  report: unknown,
  rejectSeverities: ImageScanSeverity[]
): { vulnerable: boolean; summary: ImageScanSummary } {
  if (
    !report ||
    typeof report !== 'object' ||
    Array.isArray(report) ||
    !Number.isSafeInteger((report as any).SchemaVersion) ||
    (report as any).SchemaVersion <= 0 ||
    !Array.isArray((report as any).Results)
  ) {
    throw new Error('Trivy report has an invalid shape')
  }
  if (!rejectSeverities.length) {
    throw new Error('Image scan rejection policy is empty')
  }

  const findings: ImageScanSummary['list'] = []
  for (const result of (report as any).Results) {
    if (!result || typeof result !== 'object' || Array.isArray(result)) {
      throw new Error('Trivy report contains an invalid result')
    }
    if (result.Vulnerabilities === undefined || result.Vulnerabilities === null) {
      continue
    }
    if (!Array.isArray(result.Vulnerabilities)) {
      throw new Error('Trivy report vulnerabilities must be an array')
    }
    for (const finding of result.Vulnerabilities) {
      if (
        !finding ||
        typeof finding !== 'object' ||
        Array.isArray(finding) ||
        !IMAGE_SCAN_SEVERITIES.includes(finding.Severity) ||
        typeof finding.VulnerabilityID !== 'string' ||
        typeof finding.PkgName !== 'string'
      ) {
        throw new Error('Trivy report contains an invalid vulnerability')
      }
      findings.push({
        severity: finding.Severity,
        id: finding.VulnerabilityID,
        package: finding.PkgName,
        title: typeof finding.Title === 'string' ? finding.Title : 'No description'
      })
    }
  }

  const severityRank = (severity: ImageScanSeverity) =>
    IMAGE_SCAN_SEVERITIES.indexOf(severity)
  findings.sort((left, right) => {
    const difference = severityRank(right.severity) - severityRank(left.severity)
    return difference || left.id.localeCompare(right.id)
  })

  const bySeverity = Object.fromEntries(
    IMAGE_SCAN_SEVERITIES.map((severity) => [severity, 0])
  ) as Record<ImageScanSeverity, number>
  for (const finding of findings) bySeverity[finding.severity] += 1

  return {
    vulnerable: findings.some((finding) => rejectSeverities.includes(finding.severity)),
    summary: { total: findings.length, bySeverity, list: findings }
  }
}
