import { sanitizeServiceFiles } from '../../utils/util.js'

import { BaseFileObject, EncryptMethod } from '../../@types/fileObject.js'
import { CORE_LOGGER } from '../../utils/logging/common.js'
import { ComputeJob, DBComputeJob } from '../../@types/index.js'
import { OceanNode } from '../../OceanNode.js'
export { C2DEngine } from './compute_engine_base.js'

export async function decryptFilesObject(
  serviceFiles: any
): Promise<BaseFileObject | null> {
  const node = OceanNode.getInstance()

  try {
    // 2. Decrypt the url
    const decryptedUrlBytes = await node
      .getKeyManager()
      .decrypt(
        Uint8Array.from(Buffer.from(sanitizeServiceFiles(serviceFiles), 'hex')),
        EncryptMethod.ECIES
      )

    // 3. Convert the decrypted bytes back to a string
    const decryptedFilesString = Buffer.from(decryptedUrlBytes).toString()
    const decryptedFileArray = JSON.parse(decryptedFilesString)

    return decryptedFileArray.files[0]
  } catch (err) {
    CORE_LOGGER.error('Error decrypting files object: ' + err.message)
    return null
  }
}

export function omitDBComputeFieldsFromComputeJob(dbCompute: DBComputeJob): ComputeJob {
  const computeJob: ComputeJob = {
    owner: dbCompute.owner,
    did: dbCompute.did,
    jobId: dbCompute.jobId,
    dateCreated: dbCompute.dateCreated,
    dateFinished: dbCompute.dateFinished,
    status: dbCompute.status,
    statusText: dbCompute.statusText,
    results: dbCompute.results,
    inputDID: dbCompute.inputDID,
    algoDID: dbCompute.algoDID,
    maxJobDuration: dbCompute.maxJobDuration,
    agreementId: dbCompute.agreementId,
    environment: dbCompute.environment,
    metadata: dbCompute.metadata,
    terminationDetails: dbCompute.terminationDetails,
    queueMaxWaitTime: dbCompute.queueMaxWaitTime
  }
  if (dbCompute.participantValue) computeJob.participantValue = dbCompute.participantValue
  return computeJob
}
