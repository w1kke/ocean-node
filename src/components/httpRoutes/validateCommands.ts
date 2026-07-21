import { PROTOCOL_COMMANDS, SUPPORTED_PROTOCOL_COMMANDS } from '../../utils/constants.js'
import { P2PCommandResponse } from '../../@types/OceanNode.js'
import { Command } from '../../@types/commands.js'
import { CORE_LOGGER } from '../../utils/logging/common.js'
import { ReadableString } from '../P2P/handlers.js'

export type ValidateParams = {
  valid: boolean
  reason?: string
  status?: number
}

const SENSITIVE_LOG_FIELDS = new Set([
  'accesskeyid',
  'apikey',
  'authorization',
  'cookie',
  'encrypteddockerregistryauth',
  'headers',
  'jwtsecret',
  'mnemonic',
  'password',
  'privatekey',
  'rawdata',
  'secretaccesskey',
  'signature',
  'token',
  'url',
  'xapikey'
])

function redactValueForLogging(value: any, seen: WeakSet<object>): any {
  if (Buffer.isBuffer(value)) return `[${value.length} bytes]`
  if (!value || typeof value !== 'object') return value
  if (seen.has(value)) return '[CIRCULAR]'
  seen.add(value)

  if (Array.isArray(value)) {
    return value.map((item) => redactValueForLogging(item, seen))
  }

  const redacted: Record<string, any> = {}
  for (const [key, item] of Object.entries(value)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '')
    if (key === 'stream') redacted[key] = '[STREAM]'
    else if (SENSITIVE_LOG_FIELDS.has(normalized)) redacted[key] = '[REDACTED]'
    else redacted[key] = redactValueForLogging(item, seen)
  }
  return redacted
}

export function redactCommandForLogging(commandData: any): any {
  return redactValueForLogging(commandData ?? {}, new WeakSet())
}

// add others when we add suppor

// request level validation, just check if we have a "command" field and its a supported one
// each command handler is responsible for the reamining validatio of the command fields
export function validateCommandParameters(
  commandData: any,
  requiredFields: string[]
): ValidateParams {
  if (!commandData) {
    return buildInvalidRequestMessage('Missing request body/data')
  }

  const commandStr: string = commandData.command as string

  if (!commandStr) {
    return buildInvalidRequestMessage('Invalid Request: "command" is mandatory!')
  }
  // direct commands
  else if (!SUPPORTED_PROTOCOL_COMMANDS.includes(commandStr)) {
    return buildInvalidRequestMessage(`Invalid or unrecognized command: "${commandStr}"`)
  }

  const logCommandData = redactCommandForLogging(commandData)

  if (commandStr === PROTOCOL_COMMANDS.ENCRYPT) {
    logCommandData.files = [] // hide files data (sensitive) + rawData (long buffer) from logging
  } else if (commandStr === PROTOCOL_COMMANDS.ENCRYPT_FILE && commandData.rawData) {
    logCommandData.rawData = []
  }

  CORE_LOGGER.info(
    `Checking received command data for Command "${commandStr}": ${JSON.stringify(
      logCommandData,
      null,
      4
    )}`
  )

  for (const field of requiredFields) {
    if (
      !Object.hasOwn(commandData as Command, field) ||
      commandData[field] === undefined ||
      commandData[field] === null
    ) {
      return {
        valid: false,
        status: 400,
        reason: `Missing one ( "${field}" ) or more required field(s) for command: "${commandStr}". Required fields: ${requiredFields}`
      }
    }
  }
  return {
    valid: true
  }
}

// aux function as we are repeating same block of code all the time, only thing that changes is reason msg
export function buildInvalidRequestMessage(cause: string): ValidateParams {
  return {
    valid: false,
    status: 400,
    reason: cause
  }
}

export function buildRateLimitReachedResponse(): P2PCommandResponse {
  return {
    stream: new ReadableString('Rate limit exceeded'),
    status: { httpStatus: 403, error: 'Rate limit exceeded' }
  }
}

// always send same response
export function buildInvalidParametersResponse(
  validation: ValidateParams
): P2PCommandResponse {
  return {
    stream: null,
    status: { httpStatus: validation.status, error: validation.reason }
  }
}

export function buildErrorResponse(cause: string): P2PCommandResponse {
  return {
    stream: null,
    status: {
      httpStatus: 400,
      error: `The result is not the expected one: ${cause}`
    }
  }
}
