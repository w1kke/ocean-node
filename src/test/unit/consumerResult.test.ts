import { expect } from 'chai'
import { Readable } from 'stream'
import * as tarStream from 'tar-stream'

import { readSingleJsonResultArchive } from '../../components/c2d/consumerResult.js'

type ArchiveEntry = {
  name: string
  body?: Buffer | string
  type?: 'file' | 'symlink' | 'directory'
  linkname?: string
}

async function makeArchive(entries: ArchiveEntry[]): Promise<Buffer> {
  const pack = tarStream.pack()
  const chunks: Buffer[] = []
  const complete = (async () => {
    for await (const chunk of pack) chunks.push(Buffer.from(chunk))
  })()

  for (const entry of entries) {
    const body = Buffer.isBuffer(entry.body) ? entry.body : Buffer.from(entry.body ?? '')
    pack.entry(
      {
        name: entry.name,
        type: entry.type ?? 'file',
        linkname: entry.linkname,
        size: entry.type && entry.type !== 'file' ? 0 : body.length
      },
      entry.type && entry.type !== 'file' ? undefined : body
    )
  }
  pack.finalize()
  await complete
  return Buffer.concat(chunks)
}

async function expectRejected(archive: Buffer, message: string, maxBytes = 1024) {
  let failure: Error = null
  try {
    await readSingleJsonResultArchive(Readable.from([archive]), maxBytes)
  } catch (error) {
    failure = error as Error
  }
  expect(failure?.message.toLowerCase()).to.include(message.toLowerCase())
}

describe('single JSON consumer result', () => {
  it('returns the original bytes for one bounded JSON object', async () => {
    const body = Buffer.from('{"ok":true,"value":42}')
    const archive = await makeArchive([{ name: 'result.json', body }])

    const result = await readSingleJsonResultArchive(Readable.from([archive]), 1024)

    expect(result.equals(body)).to.equal(true)
  })

  it('rejects empty, extra, duplicate, nested, and linked entries', async () => {
    await expectRejected(await makeArchive([]), 'exactly one')
    await expectRejected(
      await makeArchive([
        { name: 'result.json', body: '{}' },
        { name: 'notes.txt', body: 'private' }
      ]),
      'extra entries'
    )
    await expectRejected(
      await makeArchive([
        { name: 'result.json', body: '{}' },
        { name: 'result.json', body: '{}' }
      ]),
      'extra entries'
    )
    await expectRejected(
      await makeArchive([{ name: 'outputs/result.json', body: '{}' }]),
      'only result.json'
    )
    await expectRejected(
      await makeArchive([
        { name: 'result.json', type: 'symlink', linkname: '/private/source' }
      ]),
      'regular file'
    )
  })

  it('rejects invalid UTF-8, invalid JSON, and non-object JSON', async () => {
    await expectRejected(
      await makeArchive([{ name: 'result.json', body: Buffer.from([0xc3, 0x28]) }]),
      'valid UTF-8'
    )
    await expectRejected(
      await makeArchive([{ name: 'result.json', body: '{broken' }]),
      'valid JSON'
    )
    await expectRejected(
      await makeArchive([{ name: 'result.json', body: '[1,2,3]' }]),
      'JSON object'
    )
  })

  it('rejects content over the configured limit and truncated archives', async () => {
    await expectRejected(
      await makeArchive([{ name: 'result.json', body: '{"value":"too large"}' }]),
      'size limit',
      4
    )
    const archive = await makeArchive([{ name: 'result.json', body: '{}' }])
    await expectRejected(archive.subarray(0, 600), 'unexpected end of data')
  })
})
