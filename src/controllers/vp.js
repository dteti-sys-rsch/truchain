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

exports.fullVPCode = async (req, res)  => {
  const client = new Client({
    primaryNode: process.env.API_ENDPOINT,
    localPow: true
  })
  const didClient = new IotaIdentityClient(client)

  /*
    STEP 1: CREATING IDENTITY FOR ISSUER AND HOLDER
  */
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

  /*
    STEP 2: ISSUER CREATES AND SIGN A VERIFIABLE CREDENTIAL
  */
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

  /*
    STEP 3: ISSUER SEND VERIFIABLE CREDENTIAL TO HOLDER
    STEP 4: VERIFIER SEND RANDOM CHALLENGE TO BE SIGNED BY HOLDER
  */
  const nonce = crypto.randomBytes(16).toString('hex')
  const expires = Timestamp.nowUTC().checkedAdd(Duration.minutes(10))

  /*
    STEP 5: HOLDER CREATES A PRESENTATION
  */
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

  /*
    STEP 6: HOLDER SENDS PRESENTATION TO VERIFIER
    STEP 7: VERIFIER VALIDATES PRESENTATION
  */
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

  res.status(200).json({
    message: 'VP created and validated successfully',
    isValid: true,
    credentialJwtValidation: response.intoCredential(),
    presentation: decodedPresentation.presentation().toJSON(),
    nonce,
  })
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
  console.log('Credential Validation:', response.intoCredential())

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

exports.verifyVP = async (req, res) => {
  try {
    const { presentationJwt, nonce } = req.body

    if (!presentationJwt || !nonce) {
      throw new Error('Missing required parameters: presentationJwt and nonce')
    }

    const client = new Client({
      primaryNode: process.env.API_ENDPOINT,
      localPow: true
    })
    const didClient = new IotaIdentityClient(client)
    const resolver = new Resolver({ client: didClient })

    const jwtPresentationValidationOptions =
      new JwtPresentationValidationOptions({
        presentationVerifierOptions: new JwsVerificationOptions({ nonce })
      })

    const jwtObject = new Jwt(presentationJwt)
    const presentationHolderDID =
      JwtPresentationValidator.extractHolder(jwtObject)
    const resolvedHolder = await resolver.resolve(
      presentationHolderDID.toString()
    )

    const decodedPresentation = new JwtPresentationValidator(
      new EdDSAJwsVerifier()
    ).validate(jwtObject, resolvedHolder, jwtPresentationValidationOptions)

    const credentialValidator = new JwtCredentialValidator(
      new EdDSAJwsVerifier()
    )
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
        if (!jwt) throw new Error('Expected a JWT credential')
        return jwt
      })

    const issuers = jwtCredentials.map((jwtCredential) =>
      JwtCredentialValidator.extractIssuerFromJwt(jwtCredential).toString()
    )

    const resolvedIssuers = await resolver.resolveMultiple(issuers)

    const credentialValidations = []
    for (let i = 0; i < jwtCredentials.length; i++) {
      const validation = credentialValidator.validate(
        jwtCredentials[i],
        resolvedIssuers[i],
        validationOptions,
        FailFast.FirstError
      )
      credentialValidations.push(validation.intoCredential())
    }

    res.status(200).json({
      success: true,
      isValid: true,
      presentation: decodedPresentation.presentation().toJSON(),
      credentialValidations,
      holder: presentationHolderDID.toString()
    })
  } catch (error) {
    console.error('Error validating VP:', error)
    res.status(400).json({
      success: false,
      isValid: false,
      error: error.message
    })
  }
}
