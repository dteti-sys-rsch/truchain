const {
  Credential,
  EdDSAJwsVerifier,
  FailFast,
  JwkMemStore,
  JwsSignatureOptions,
  JwtCredentialValidationOptions,
  JwtCredentialValidator,
  KeyIdMemStore,
  Storage
} = require('@iota/identity-wasm/node')
const { Client } = require('@iota/sdk-wasm/node')
const { createDid } = require('../utils/did')
const { v4: uuidv4 } = require('uuid')

const client = new Client({
  primaryNode: process.env.API_ENDPOINT,
  localPow: true
})

async function createIssuerDID() {
  try {
    const issuerSecretManager = { mnemonic: process.env.ISSUER_MNEMONIC }
    const { document: issuerDocument, fragment: issuerFragment, storage: issuerStorage } =
      await createDid(client, issuerSecretManager)

    return {
      issuerDocument,
      issuerFragment,
      issuerStorage
    }
  } catch (error) {
    console.error('Error creating DID:', error)
    throw new Error('Failed to create Issuer DID: ' + error.message)
  }
}

exports.createVC = async (req, res) => {
  const metrics = {
    startTime: process.hrtime.bigint(),
    steps: {},
    success: false,
    error: null
  }

  const {
    legalName,
    registrationNumber,
    entityType,
    jurisdiction,
    issueDate,
    expirationDate,
    holderDIDId
  } = req.body

  const issuerDID = await createIssuerDID()

  const subject = {
    id: holderDIDId,
    legalName,
    registrationNumber,
    entityType,
    jurisdiction,
    issueDate,
    expirationDate
  }

  const uniqueId = uuidv4()

  metrics.steps.start = process.hrtime.bigint()
  const unsignedVc = new Credential({
    id: `https://tdlaas.aufarhmn.my.id/vc/${uniqueId}`,
    type: ['VerifiableCredential', 'RegisteredBankCredential'],
    issuer: issuerDID.issuerDocument.id(),
    credentialSubject: subject
  })

  const credentialJwt = await issuerDID.issuerDocument.createCredentialJwt(
    issuerDID.issuerStorage,
    issuerDID.issuerFragment,
    unsignedVc,
    new JwsSignatureOptions()
  )

  // No error thrown means that the credential is valid
  const response = new JwtCredentialValidator(new EdDSAJwsVerifier()).validate(
    credentialJwt,
    issuerDID.issuerDocument,
    new JwtCredentialValidationOptions(),
    FailFast.FirstError
  )
  metrics.steps.stop = process.hrtime.bigint()
  metrics.success = true

  // Commented code only for testing purpose
  res.status(200).json({
    message: 'VC created successfully',
    // unsignedVc: unsignedVc.toJSON(),
    credentialJwt,
    uniqueId,
    metrics,
    durations: {
      duration: Number(metrics.steps.stop - metrics.steps.start) / 1e6
    },
    // credentialValidation: response.intoCredential().toJSON()
  })
}
