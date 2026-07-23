import { expect } from 'chai'
import { ethers } from 'ethers'
import sinon from 'sinon'

import { Escrow } from '../../components/core/utils/escrow.js'
import { create256Hash } from '../../utils/crypt.js'

describe('escrow settlement transaction preparation', () => {
  afterEach(() => sinon.restore())

  it('derives the transaction hash before broadcasting', async () => {
    const escrow = new Escrow({} as any, 60, {} as any)
    const rawTransaction = '0x1234'
    const signer = {
      getAddress: sinon.stub().resolves('0x1111111111111111111111111111111111111111'),
      populateTransaction: sinon.stub().resolves({ to: '0x2', data: '0x3' }),
      signTransaction: sinon.stub().resolves(rawTransaction)
    }
    const claim = Object.assign(sinon.stub(), {
      estimateGas: sinon.stub().resolves(100n),
      populateTransaction: sinon.stub().resolves({ to: '0x2', data: '0x3' })
    })
    sinon.stub(escrow as any, 'getBlockchain').returns({
      getSigner: sinon.stub().resolves(signer),
      getGasOptions: sinon.stub().resolves({ gasLimit: 120n })
    })
    sinon.stub(escrow, 'getContract').returns({ claimLockAndWithdraw: claim } as any)
    sinon.stub(escrow, 'getPaymentAmountInWei').resolves('5')
    sinon.stub(escrow, 'getLocks').resolves([
      {
        jobId: create256Hash('job'),
        token: '0x2222222222222222222222222222222222222222',
        payer: '0x3333333333333333333333333333333333333333'
      }
    ] as any)

    const prepared = await escrow.prepareClaimLock(
      1,
      'job',
      '0x2222222222222222222222222222222222222222',
      '0x3333333333333333333333333333333333333333',
      0.25,
      '{}'
    )

    expect(prepared).to.deep.equal({
      transactionHash: ethers.keccak256(rawTransaction),
      rawTransaction
    })
    expect(signer.signTransaction.calledOnce).to.equal(true)
  })

  it('rebroadcasts only the signed transaction matching the persisted hash', async () => {
    const escrow = new Escrow({} as any, 60, {} as any)
    const rawTransaction = '0x1234'
    const transactionHash = ethers.keccak256(rawTransaction)
    const provider = {
      broadcastTransaction: sinon.stub().resolves({ hash: transactionHash }),
      getTransaction: sinon.stub().resolves(null)
    }
    sinon.stub(escrow as any, 'getBlockchain').returns({
      getProvider: sinon.stub().resolves(provider)
    })

    expect(
      await escrow.broadcastSettlementTransaction(1, rawTransaction, transactionHash)
    ).to.equal(transactionHash)
    let mismatch: Error | undefined
    try {
      await escrow.broadcastSettlementTransaction(
        1,
        rawTransaction,
        `0x${'0'.repeat(64)}`
      )
    } catch (error) {
      mismatch = error as Error
    }
    expect(mismatch?.message).to.contain('hash mismatch')
    expect(provider.broadcastTransaction.calledOnce).to.equal(true)
  })
})
