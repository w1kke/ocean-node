import { Readable, Transform } from 'stream'
import { pipeline } from 'node:stream/promises'
import * as tarStream from 'tar-stream'

const MAX_ARCHIVE_OVERHEAD_BYTES = 64 * 1024

export async function readSingleJsonResultArchive(
  archive: Readable,
  maxBytes: number
): Promise<Buffer> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new Error('Invalid singleJson result size limit')
  }

  const extract = tarStream.extract()
  let archiveBytes = 0
  let entryCount = 0
  let result: Buffer = null
  let failure: Error = null

  const archiveLimiter = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      archiveBytes += chunk.length
      if (archiveBytes > maxBytes + MAX_ARCHIVE_OVERHEAD_BYTES) {
        callback(new Error('Result archive exceeds the configured size limit'))
        return
      }
      callback(null, chunk)
    }
  })

  extract.on('entry', (header, stream, next) => {
    entryCount += 1
    const chunks: Buffer[] = []
    let entryBytes = 0

    if (entryCount !== 1) failure ??= new Error('Result archive has extra entries')
    if (header.name !== 'result.json') {
      failure ??= new Error('Result archive must contain only result.json')
    }
    if (header.type !== 'file') {
      failure ??= new Error('result.json must be a regular file')
    }
    if (!Number.isSafeInteger(header.size) || header.size < 0 || header.size > maxBytes) {
      failure ??= new Error('result.json exceeds the configured size limit')
    }

    stream.on('data', (chunk: Buffer) => {
      entryBytes += chunk.length
      if (entryBytes > maxBytes) {
        failure ??= new Error('result.json exceeds the configured size limit')
      } else {
        chunks.push(Buffer.from(chunk))
      }
    })
    stream.once('error', (error) => {
      failure ??= error
    })
    stream.once('end', () => {
      if (header.size !== entryBytes) {
        failure ??= new Error('result.json archive entry is truncated')
      }
      if (entryCount === 1 && !failure) result = Buffer.concat(chunks)
      next()
    })
  })

  await pipeline(archive, archiveLimiter, extract)

  if (failure) throw failure
  if (entryCount !== 1 || !result) {
    throw new Error('Result archive must contain exactly one result.json file')
  }

  let decoded: string
  try {
    decoded = new TextDecoder('utf-8', { fatal: true }).decode(result)
  } catch {
    throw new Error('result.json is not valid UTF-8')
  }

  let value: unknown
  try {
    value = JSON.parse(decoded)
  } catch {
    throw new Error('result.json is not valid JSON')
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('result.json must contain a JSON object')
  }

  return result
}
