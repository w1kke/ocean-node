import express from 'express'
import { SERVICES_API_BASE_PATH } from '../../utils/constants.js'

export const personalInsightRoutes = express.Router()

function exactBody(value: unknown, keys: string[]): Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')
  ) {
    throw new Error('not_found')
  }
  return value as Record<string, unknown>
}

function unavailable(res: express.Response): void {
  res
    .status(404)
    .set({
      'Cache-Control': 'private, no-store',
      'X-Content-Type-Options': 'nosniff'
    })
    .json({ error: 'not_found' })
}

personalInsightRoutes.post(
  `${SERVICES_API_BASE_PATH}/personal-insights/runs/start`,
  async (req, res) => {
    try {
      const body = exactBody(req.body, ['grant'])
      if (typeof body.grant !== 'string') throw new Error('not_found')
      const result = await req.oceanNode.getC2DEngines().startPersonalInsight(body.grant)
      res
        .status(202)
        .set({
          'Cache-Control': 'private, no-store',
          'X-Content-Type-Options': 'nosniff'
        })
        .json(result)
    } catch {
      unavailable(res)
    }
  }
)

personalInsightRoutes.post(
  `${SERVICES_API_BASE_PATH}/personal-insights/runs/status`,
  async (req, res) => {
    try {
      const body = exactBody(req.body, ['runId', 'capability'])
      if (typeof body.runId !== 'string' || typeof body.capability !== 'string') {
        throw new Error('not_found')
      }
      const result = await req.oceanNode
        .getC2DEngines()
        .getPersonalInsightStatus(body.runId, body.capability)
      res
        .status(200)
        .set({
          'Cache-Control': 'private, no-store',
          'X-Content-Type-Options': 'nosniff'
        })
        .json(result)
    } catch {
      unavailable(res)
    }
  }
)

personalInsightRoutes.post(
  `${SERVICES_API_BASE_PATH}/personal-insights/runs/revalidate`,
  async (req, res) => {
    try {
      const body = exactBody(req.body, ['grant', 'runId'])
      if (typeof body.grant !== 'string' || typeof body.runId !== 'string') {
        throw new Error('not_found')
      }
      await req.oceanNode
        .getC2DEngines()
        .revalidatePersonalInsight(body.grant, body.runId, req.get('Authorization') ?? '')
      res
        .status(204)
        .set({
          'Cache-Control': 'private, no-store',
          'X-Content-Type-Options': 'nosniff'
        })
        .send()
    } catch {
      unavailable(res)
    }
  }
)

personalInsightRoutes.post(
  `${SERVICES_API_BASE_PATH}/personal-insights/runs/result`,
  async (req, res) => {
    try {
      const body = exactBody(req.body, ['runId', 'capability'])
      if (typeof body.runId !== 'string' || typeof body.capability !== 'string') {
        throw new Error('not_found')
      }
      const result = await req.oceanNode
        .getC2DEngines()
        .getPersonalInsightResult(body.runId, body.capability)
      res
        .status(200)
        .set({
          'Content-Type': 'application/json; charset=utf-8',
          'Content-Length': String(result.bytes.length),
          'X-Content-SHA256': result.checksum,
          'Cache-Control': 'private, no-store',
          'X-Content-Type-Options': 'nosniff'
        })
        .send(result.bytes)
    } catch {
      unavailable(res)
    }
  }
)
