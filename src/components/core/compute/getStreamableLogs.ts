import { P2PCommandResponse } from '../../../@types/index.js'
import { CommandHandler } from '../handler/handler.js'
import { ComputeGetStreamableLogsCommand } from '../../../@types/commands.js'
import {
  buildInvalidRequestMessage,
  validateCommandParameters,
  ValidateParams
} from '../../httpRoutes/validateCommands.js'
import { isAddress } from 'ethers'

export class ComputeGetStreamableLogsHandler extends CommandHandler {
  validate(command: ComputeGetStreamableLogsCommand): ValidateParams {
    const validation = validateCommandParameters(command, ['jobId'])
    if (validation.valid) {
      if (command.consumerAddress && !isAddress(command.consumerAddress)) {
        return buildInvalidRequestMessage(
          'Parameter : "consumerAddress" is not a valid web3 address'
        )
      }
    }
    return validation
  }

  async handle(task: ComputeGetStreamableLogsCommand): Promise<P2PCommandResponse> {
    const validationResponse = await this.verifyParamsAndRateLimits(task)
    if (this.shouldDenyTaskHandling(validationResponse)) {
      return validationResponse
    }
    return {
      stream: null,
      status: {
        httpStatus: 403,
        error: 'Compute logs are operator-only'
      }
    }
  }
}
