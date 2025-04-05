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
const { createDid } = require('../utils/did.js')

exports.createVC = async (req, res) => {
  const client = new Client({
    primaryNode: process.env.API_ENDPOINT,
    localPow: true
  })

  const secretManager = {
    mnemonic: process.env.MNEMONIC
  }

  const issuerStorage = new Storage(new JwkMemStore(), new KeyIdMemStore())
  const { document: issuerDocument, fragment: issuerFragment } =
    await createDid(client, secretManager, issuerStorage)

  const aliceStorage = new Storage(new JwkMemStore(), new KeyIdMemStore())
  const { document: aliceDocument } = await createDid(
    client,
    secretManager,
    aliceStorage
  )

  const subject = {
    id: aliceDocument.id(),
    name: 'Alice',
    degreeName: 'Bachelor of Science and Arts',
    degreeType: 'BachelorDegree',
    GPA: '4.0'
  }

  const unsignedVc = new Credential({
    id: 'https://example.edu/credentials/3732',
    type: 'UniversityDegreeCredential',
    issuer: issuerDocument.id(),
    credentialSubject: subject
  })

  const credentialJwt = await issuerDocument.createCredentialJwt(
    issuerStorage,
    issuerFragment,
    unsignedVc,
    new JwsSignatureOptions()
  )

  const decoded_credential = new JwtCredentialValidator(
    new EdDSAJwsVerifier()
  ).validate(
    credentialJwt,
    issuerDocument,
    new JwtCredentialValidationOptions(),
    FailFast.FirstError
  )

  res.status(200).json({
    credentialJwt: credentialJwt.toString(),
    credential: decoded_credential.intoCredential(),
    issuerDocument: issuerDocument.toString(),
    issuerFragment: issuerFragment,
    aliceDocument: aliceDocument.toString()
  })
}
