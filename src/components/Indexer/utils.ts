import { ethers } from 'ethers'
import fs from 'fs'
import { homedir } from 'os'
import { EVENTS, EVENT_HASHES } from '../../utils/constants.js'
import { NetworkEvent } from '../../@types/blockchain.js'
import {
  CustomNodeLogger,
  LOGGER_MODULE_NAMES,
  LOG_LEVELS_STR,
  defaultConsoleTransport,
  getCustomLoggerForModule
} from '../../utils/logging/Logger.js'

export const INDEXER_LOGGER: CustomNodeLogger = getCustomLoggerForModule(
  LOGGER_MODULE_NAMES.INDEXER,
  LOG_LEVELS_STR.LEVEL_INFO,
  defaultConsoleTransport
)

export const getDeployedContractBlock = async (network: number) => {
  let deployedBlock: number
  const addressFile = JSON.parse(
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    fs.readFileSync(
      process.env.ADDRESS_FILE ||
        `${homedir}/.ocean/ocean-contracts/artifacts/address.json`,
      'utf8'
    )
  )
  const networkKeys = Object.keys(addressFile)
  networkKeys.forEach((key) => {
    if (addressFile[key].chainId === network) {
      deployedBlock = addressFile[key].startBlock
    }
  })
  return deployedBlock
}

export const getNetworkHeight = async (provider: ethers.Provider) => {
  const networkHeight = await provider.getBlockNumber()

  return networkHeight
}

export const processBlocks = async (
  provider: ethers.Provider,
  startIndex: number,
  count: number
) => {
  let processedBlocks = 0

  for (let blockNumber = startIndex; blockNumber < startIndex + count; blockNumber++) {
    const block = await provider.getBlock(blockNumber)

    const processedEvents = await processBlockEvents(provider, block)

    processedBlocks += processedEvents.length
  }

  return processedBlocks
}

const processBlockEvents = async (provider: ethers.Provider, block: ethers.Block) => {
  const processedEvents = []
  for (const transaction of block.transactions) {
    const receipt = await provider.getTransactionReceipt(transaction)
    if (receipt?.logs) {
      const processedEventData = await processEventData(receipt?.logs)
      if (processedEventData) {
        processedEvents.push(processedEventData)
      }
    } else {
      continue
    }
  }
  return processedEvents
}

function findEventByKey(keyToFind: string): NetworkEvent {
  for (const [key, value] of Object.entries(EVENT_HASHES)) {
    if (key === keyToFind) {
      INDEXER_LOGGER.logMessage(`Found event with key '${key}':  ${value}`, true)
      return value
    }
  }
  return null
}

export const processEventData = async (
  logs: readonly ethers.Log[],
  provider?: ethers.Provider
) => {
  if (logs.length > 0) {
    for (const log of logs) {
      const event = findEventByKey(log.topics[0])
      if (
        event &&
        (event.type === EVENTS.METADATA_CREATED ||
          event.type === EVENTS.METADATA_UPDATED ||
          event.type === EVENTS.METADATA_STATE)
      ) {
        INDEXER_LOGGER.logMessage(
          'METADATA_CREATED || METADATA_UPDATED || METADATA_STATE   -- ',
          true
        )
        return await processMetadataEvents()
      } else if (event && event.type === EVENTS.EXCHANGE_CREATED) {
        INDEXER_LOGGER.logMessage('-- EXCHANGE_CREATED -- ', true)
        return procesExchangeCreated()
      } else if (event && event.type === EVENTS.EXCHANGE_RATE_CHANGED) {
        INDEXER_LOGGER.logMessage('-- EXCHANGE_RATE_CHANGED -- ', true)
        return await processExchangeRateChanged()
      } else if (event && event.type === EVENTS.ORDER_STARTED) {
        INDEXER_LOGGER.logMessage('-- ORDER_STARTED -- ', true)
        return await procesOrderStarted()
      } else if (event && event.type === EVENTS.TOKEN_URI_UPDATE) {
        INDEXER_LOGGER.logMessage('-- TOKEN_URI_UPDATE -- ', true)
        return await processTokenUriUpadate()
      }
    }
  }

  return 'EVENT_NOT_FOUND'
}

const processMetadataEvents = async (): Promise<string> => {
  return 'METADATA_CREATED'
}

const procesExchangeCreated = async (): Promise<string> => {
  return 'EXCHANGE_CREATED'
}

const processExchangeRateChanged = async (): Promise<string> => {
  return 'EXCHANGE_RATE_CHANGED'
}

const procesOrderStarted = async (): Promise<string> => {
  return 'ORDER_STARTED'
}

const processTokenUriUpadate = async (): Promise<string> => {
  return 'TOKEN_URI_UPDATE'
}
