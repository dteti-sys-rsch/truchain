const {
  Credential,
  Duration,
  EdDSAJwsVerifier,
  FailFast,
  IotaIdentityClient,
  JwkMemStore,
  JwsSignatureOptions,
  JwsVerificationOptions,
  Jwt,
  JwtCredentialValidationOptions,
  JwtCredentialValidator,
  JwtPresentationOptions,
  JwtPresentationValidationOptions,
  JwtPresentationValidator,
  KeyIdMemStore,
  Presentation,
  Resolver,
  Storage,
  SubjectHolderRelationship,
  Timestamp
} = require('@iota/identity-wasm/node')
const { Client } = require('@iota/sdk-wasm/node')
const { createDid } = require('../utils/did')
const crypto = require('crypto')
const { type } = require('os')

exports.fullVPCode = async (req) => {
  const client = new Client({
    primaryNode: process.env.API_ENDPOINT,
    localPow: true
  })
  const didClient = new IotaIdentityClient(client)

  const issuerSecretManager = {
    mnemonic: process.env.TEST_MNEMONIC_1
  }
  const issuerStorage = new Storage(new JwkMemStore(), new KeyIdMemStore())
  const { document: issuerDocument, fragment: issuerFragment } =
    await createDid(client, issuerSecretManager, issuerStorage)

  const aliceSecretManager = {
    mnemonic: process.env.TEST_MNEMONIC_2
  }
  const aliceStorage = new Storage(new JwkMemStore(), new KeyIdMemStore())
  const { document: aliceDocument, fragment: aliceFragment } = await createDid(
    client,
    aliceSecretManager,
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

  const response = new JwtCredentialValidator(new EdDSAJwsVerifier()).validate(
    credentialJwt,
    issuerDocument,
    new JwtCredentialValidationOptions(),
    FailFast.FirstError
  )
  console.log('credentialjwt validation', response.intoCredential())

  console.log('Sending credential (as JWT) to the holder', unsignedVc.toJSON())

  const nonce = crypto.randomBytes(16).toString('hex')
  const expires = Timestamp.nowUTC().checkedAdd(Duration.minutes(10))

  const unsignedVp = new Presentation({
    holder: aliceDocument.id(),
    verifiableCredential: [credentialJwt]
  })

  const presentationJwt = await aliceDocument.createPresentationJwt(
    aliceStorage,
    aliceFragment,
    unsignedVp,
    new JwsSignatureOptions({ nonce }),
    new JwtPresentationOptions({ expirationDate: expires })
  )

  console.log(
    'Sending presentation (as JWT) to the verifier',
    unsignedVp.toJSON()
  )

  const jwtPresentationValidationOptions = new JwtPresentationValidationOptions(
    {
      presentationVerifierOptions: new JwsVerificationOptions({ nonce })
    }
  )

  const resolver = new Resolver({ client: didClient })
  const presentationHolderDID =
    JwtPresentationValidator.extractHolder(presentationJwt)
  const resolvedHolder = await resolver.resolve(
    presentationHolderDID.toString()
  )

  const decodedPresentation = new JwtPresentationValidator(
    new EdDSAJwsVerifier()
  ).validate(presentationJwt, resolvedHolder, jwtPresentationValidationOptions)

  const credentialValidator = new JwtCredentialValidator(new EdDSAJwsVerifier())
  const validationOptions = new JwtCredentialValidationOptions({
    subjectHolderRelationship: [
      presentationHolderDID.toString(),
      SubjectHolderRelationship.AlwaysSubject
    ]
  })

  const jwtCredentials = decodedPresentation
    .presentation()
    .verifiableCredential()
    .map((credential) => {
      const jwt = credential.tryIntoJwt()
      if (!jwt) throw new Error('expected a JWT credential')
      return jwt
    })

  const issuers = jwtCredentials.map((jwtCredential) =>
    JwtCredentialValidator.extractIssuerFromJwt(jwtCredential).toString()
  )

  const resolvedIssuers = await resolver.resolveMultiple(issuers)

  for (let i = 0; i < jwtCredentials.length; i++) {
    credentialValidator.validate(
      jwtCredentials[i],
      resolvedIssuers[i],
      validationOptions,
      FailFast.FirstError
    )
  }

  console.log('VP successfully validated')
}

/*
    BEGIN CODE FOR TESTING
*/
// In-memory nonce store (use Redis or DB in prod)
const nonceStore = new Map()

exports.createVP = async (req, res) => {
  const client = new Client({
    primaryNode: process.env.API_ENDPOINT,
    localPow: true
  })

  const issuerSecretManager = { mnemonic: process.env.TEST_MNEMONIC_1 }
  const issuerStorage = new Storage(new JwkMemStore(), new KeyIdMemStore())
  const { document: issuerDocument, fragment: issuerFragment } =
    await createDid(client, issuerSecretManager, issuerStorage)

  const aliceSecretManager = { mnemonic: process.env.TEST_MNEMONIC_2 }
  const aliceStorage = new Storage(new JwkMemStore(), new KeyIdMemStore())
  const { document: aliceDocument, fragment: aliceFragment } = await createDid(
    client,
    aliceSecretManager,
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

  const response = new JwtCredentialValidator(new EdDSAJwsVerifier()).validate(
    credentialJwt,
    issuerDocument,
    new JwtCredentialValidationOptions(),
    FailFast.FirstError
  )
  console.log('credentialjwt validation', response.intoCredential())

  // Generate dynamic nonce + expiration
  const nonce = crypto.randomBytes(16).toString('hex')
  const expires = Timestamp.nowUTC().checkedAdd(Duration.minutes(30))

  nonceStore.set(nonce, { did: aliceDocument.id().toString(), expires })

  const unsignedVp = new Presentation({
    holder: aliceDocument.id(),
    verifiableCredential: [credentialJwt]
  })

  const presentationJwt = await aliceDocument.createPresentationJwt(
    aliceStorage,
    aliceFragment,
    unsignedVp,
    new JwsSignatureOptions({ nonce }),
    new JwtPresentationOptions({ expirationDate: expires })
  )

  return res.json({
    presentationJwt: presentationJwt.toString(),
    nonce,
    vp: unsignedVp.toJSON()
  })
}

