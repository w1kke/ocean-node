import { Handler } from './handler.js'
import { GetFeesCommand } from '../../@types/commands.js'
import { P2PCommandResponse } from '../../@types/OceanNode.js'
import { createProviderFee } from './utils/feesHandler.js'
import { Readable } from 'stream'
import { GENERIC_EMOJIS, LOG_LEVELS_STR } from '../../utils/logging/Logger.js'
import { PROVIDER_LOGGER } from '../../utils/logging/common.js'
import {
  ValidateParams,
  buildInvalidParametersResponse,
  validateCommandParameters
} from '../httpRoutes/validateCommands.js'

export class FeesHandler extends Handler {
  validate(command: GetFeesCommand): ValidateParams {
    return validateCommandParameters(command, ['ddo', 'serviceId'])
  }

  async handle(task: GetFeesCommand): Promise<P2PCommandResponse> {
    const validation = this.validate(task)
    if (!validation.valid) {
      return buildInvalidParametersResponse(validation)
    }
    PROVIDER_LOGGER.logMessage(
      `Try to calculate fees for DDO with id: ${task.ddoId} and serviceId: ${task.serviceId}`,
      true
    )
    let errorMsg: string = null
    if (!task.ddoId) {
      errorMsg = 'Missing ddo id'
    }
    if (!task.serviceId) {
      errorMsg = 'Missing service id'
    }

    const ddo = await this.getOceanNode().getDatabase().ddo.retrieve(task.ddoId)

    if (!ddo) {
      errorMsg = 'Cannot resolve DID'
    }

    const service = ddo.services.find((what: any) => what.id === task.serviceId)
    if (!service) {
      errorMsg = 'Invalid serviceId'
    }
    if (service.type === 'compute') {
      errorMsg = 'Use the initializeCompute endpoint to initialize compute jobs'
    }
    const now = new Date().getTime() / 1000
    let validUntil = service.timeout === 0 ? 0 : now + service.timeout // first, make it service default
    if (task.validUntil && !isNaN(task.validUntil)) {
      // so user input is a number
      if (service.timeout > 0 && task.validUntil > validUntil) {
        errorMsg = 'Required validUntil is higher than service timeout'
      }
      // eslint-disable-next-line prefer-destructuring
      validUntil = task.validUntil
    }

    if (errorMsg) {
      PROVIDER_LOGGER.logMessageWithEmoji(
        errorMsg,
        true,
        GENERIC_EMOJIS.EMOJI_CROSS_MARK,
        LOG_LEVELS_STR.LEVEL_ERROR
      )
      return {
        stream: null,
        status: {
          httpStatus: 500,
          error: errorMsg
        }
      }
    }

    try {
      const providerFee = await createProviderFee(ddo, service, validUntil, null, null)
      if (providerFee) {
        return {
          stream: Readable.from(JSON.stringify(providerFee, null, 4)),
          status: { httpStatus: 200 }
        }
      } else {
        const error = `Unable to calculate fees (null) for DDO with id: ${task.ddoId} and serviceId: ${task.serviceId}`
        PROVIDER_LOGGER.logMessageWithEmoji(
          error,
          true,
          GENERIC_EMOJIS.EMOJI_CROSS_MARK,
          LOG_LEVELS_STR.LEVEL_ERROR
        )
        return {
          stream: null,
          status: {
            httpStatus: 500,
            error
          }
        }
      }
    } catch (error) {
      PROVIDER_LOGGER.logMessageWithEmoji(
        error.message,
        true,
        GENERIC_EMOJIS.EMOJI_CROSS_MARK,
        LOG_LEVELS_STR.LEVEL_ERROR
      )
      return {
        stream: null,
        status: {
          httpStatus: 500,
          error: error.message
        }
      }
    }
  }
}
