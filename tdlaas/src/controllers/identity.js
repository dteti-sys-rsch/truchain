const {
  EdDSAJwsVerifier,
  FailFast,
  IotaIdentityClient,
  JwsVerificationOptions,
  Jwt,
  JwtCredentialValidationOptions,
  JwtCredentialValidator,
  JwtPresentationValidationOptions,
  JwtPresentationValidator,
  Resolver,
  SubjectHolderRelationship
} = require('@iota/identity-wasm/node')
const { Client } = require('@iota/sdk-wasm/node')
const crypto = require('crypto')
const redisClient = require('../config/redis')

exports.initConnection = async (req, res) => {
  const { id } = req.params
  const nonce = crypto.randomBytes(16).toString('hex')

  redisClient
    .set(`id:${id}`, nonce, { EX: 300 })
    .then(() => {
      res.status(200).json({ message: 'Nonce generated', nonce })
    })
    .catch((err) => {
      console.error('Error storing nonce in Redis:', err)
      res.status(500).json({ error: 'Failed to store nonce' })
    })
}

exports.verifyVP = async (req, res) => {
  try {
    const { presentationJwt, uniqueId } = req.body

    if (!presentationJwt || !uniqueId) {
      throw new Error(
        'Missing required parameters: presentationJwt and uniqueId'
      )
    }

    const nonce = await redisClient.get(`id:${uniqueId}`)
    if (!nonce) {
      throw new Error('Invalid or expired nonce')
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

    // Delete the nonce after successful validation
    await redisClient.del(`id:${uniqueId}`)

    res.status(200).json({
      message: 'VP validated successfully!',
      success: true,
      isValid: true,
      presentation: decodedPresentation.presentation().toJSON(),
      credentialValidations,
      holder: presentationHolderDID.toString()
    })
  } catch (error) {
    console.error('Error validating VP:', error)
    res.status(400).json({
      message: 'VP validation failed!',
      success: false,
      isValid: false,
      error: error.message
    })
  }
}
