const {
  Credential,
  EdDSAJwsVerifier,
  FailFast,
  JwsSignatureOptions,
  JwtCredentialValidationOptions,
  JwtCredentialValidator
} = require('@iota/identity-wasm/node')
const { Client } = require('@iota/sdk-wasm/node')
const { createDid } = require('../utils/did')
const { v4: uuidv4 } = require('uuid')

const client = new Client({
  primaryNode: process.env.API_ENDPOINT,
  localPow: true
})

async function createHolderDID() {
  try {
    const holderSecretManager = { mnemonic: process.env.HOLDER_MNEMONIC }
    const {
      document: holderDocument,
      fragment: holderFragment,
      storage: holderStorage
    } = await createDid(client, holderSecretManager)

    return {
      holderDocument,
      holderFragment,
      holderStorage
    }
  } catch (error) {
    console.error('Error creating DID:', error)
    throw new Error('Failed to creat Holder DID: ' + error.message)
  }
}

exports.createVC = async (req, res) => {
  const { transactions } = req.body

  const holderDID = await createHolderDID()

  const subject = {
    id: holderDID.holderDocument.id(),
    transactions: transactions.map((tx) => ({
      timestamp: tx.timestamp,
      fromBank: tx.fromBank,
      fromAccount: tx.fromAccount,
      toBank: tx.toBank,
      toAccount: tx.toAccount,
      amountReceived: tx.amountReceived,
      receivingCurrency: tx.receivingCurrency,
      amountPaid: tx.amountPaid,
      paymentCurrency: tx.paymentCurrency,
      paymentFormat: tx.paymentFormat
    }))
  }

  const uniqueId = uuidv4()

  const unsignedVc = new Credential({
    id: `https://tdlaas.aufarhmn.my.id/data/${uniqueId}`,
    type: ['VerifiableCredential', 'VerifiableData'],
    issuer: holderDID.holderDocument.id(),
    credentialSubject: subject
  })

  const credentialJwt = await holderDID.holderDocument.createCredentialJwt(
    holderDID.holderStorage,
    holderDID.holderFragment,
    unsignedVc,
    new JwsSignatureOptions()
  )

  const response = new JwtCredentialValidator(new EdDSAJwsVerifier()).validate(
    credentialJwt,
    holderDID.holderDocument,
    new JwtCredentialValidationOptions(),
    FailFast.FirstError
  )

  res.status(200).json({
    message: 'VC created successfully',
    credentialJwt,
    uniqueId
  })
}
