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
    const issuerStorage = new Storage(new JwkMemStore(), new KeyIdMemStore())
    const { document: issuerDocument, fragment: issuerFragment } =
      await createDid(client, issuerSecretManager, issuerStorage)

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

  const unsignedVc = new Credential({
    id: `https://tdlaas.aufarhmn.my.id/vc/${uuidv4()}`,
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

  const response = new JwtCredentialValidator(new EdDSAJwsVerifier()).validate(
    credentialJwt,
    issuerDID.issuerDocument,
    new JwtCredentialValidationOptions(),
    FailFast.FirstError
  )

  res.status(200).json({
    message: 'VC created successfully',
    unsignedVc: unsignedVc.toJSON(),
    credentialJwt,
    credentialValidation: response.intoCredential().toJSON()
  })
}
