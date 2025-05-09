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
  const metrics = {
    startTime: process.hrtime.bigint(),
    steps: {},
    success: false,
    error: null
  }

  try {
    const { id } = req.params

    // 1. Generate nonce
    metrics.steps.challengeGenerationStart = process.hrtime.bigint()
    const nonce = crypto.randomBytes(16).toString('hex')
    metrics.steps.challengeGenerationEnd = process.hrtime.bigint()

    metrics.steps.redisSetStart = process.hrtime.bigint()
    await redisClient.set(`id:${id}`, nonce)
    metrics.steps.redisSetEnd = process.hrtime.bigint()

    // 3. Calculate durations
    const durations = {
      challengeGen:
        Number(
          metrics.steps.challengeGenerationEnd -
            metrics.steps.challengeGenerationStart
        ) / 1e6,
      redisSet:
        Number(metrics.steps.redisSetEnd - metrics.steps.redisSetStart) / 1e6,
      total: Number(process.hrtime.bigint() - metrics.startTime) / 1e6
    }

    metrics.success = true

    res.status(200).json({
      success: true,
      nonce,
      metrics: {
        durations,
        redisKey: `id:${id}`
      }
    })
  } catch (err) {
    metrics.error = err.message
    metrics.endTime = process.hrtime.bigint()

    console.error('Init connection failed:', {
      error: err,
      params: req.params,
      metrics
    })

    res.status(500).json({
      success: false,
      error: 'Failed to initialize connection',
      details: err.message
    })
  }
}

exports.verifyVP = async (req, res) => {
  const metrics = {
    startTime: process.hrtime.bigint(),
    steps: {},
    success: false,
    error: null
  }

  try {
    const { presentationJwt, uniqueId } = req.body

    // Input validation
    metrics.steps.inputValidationStart = process.hrtime.bigint()
    if (!presentationJwt || !uniqueId) {
      throw new Error(
        'Missing required parameters: presentationJwt and uniqueId'
      )
    }
    metrics.steps.inputValidationEnd = process.hrtime.bigint()

    // Nonce retrieval
    metrics.steps.nonceRetrievalStart = process.hrtime.bigint()
    const nonce = await redisClient.get(`id:${uniqueId}`)
    if (!nonce) {
      throw new Error('Invalid or expired nonce')
    }
    metrics.steps.nonceRetrievalEnd = process.hrtime.bigint()

    // DID Client setup
    metrics.steps.clientSetupStart = process.hrtime.bigint()
    const client = new Client({
      primaryNode: process.env.API_ENDPOINT,
      localPow: true
    })
    const didClient = new IotaIdentityClient(client)
    const resolver = new Resolver({ client: didClient })
    metrics.steps.clientSetupEnd = process.hrtime.bigint()

    // Presentation validation
    metrics.steps.presentationValidationStart = process.hrtime.bigint()
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
    metrics.steps.presentationValidationEnd = process.hrtime.bigint()

    // Credential validation
    metrics.steps.credentialValidationStart = process.hrtime.bigint()
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
    metrics.steps.credentialValidationEnd = process.hrtime.bigint()

    // Ignore cleanup on testing scenario
    // Cleanup
    // metrics.steps.cleanupStart = process.hrtime.bigint()
    // await redisClient.del(`id:${uniqueId}`)
    // metrics.steps.cleanupEnd = process.hrtime.bigint()

    metrics.endTime = process.hrtime.bigint()
    metrics.success = true

    // Calculate durations
    const durations = calculateDurations(metrics)

    res.status(200).json({
      message: 'VP validated successfully!',
      success: true,
      isValid: true,
      presentation: decodedPresentation.presentation().toJSON(),
      credentialValidations,
      holder: presentationHolderDID.toString(),
      metrics: durations
    })
  } catch (error) {
    metrics.endTime = process.hrtime.bigint()
    metrics.error = error.message

    console.error('Error validating VP:', error)
    res.status(400).json({
      message: 'VP validation failed!',
      success: false,
      isValid: false,
      error: error.message,
      metrics: metrics.error ? calculateDurations(metrics) : null
    })
  }
}

function calculateDurations(metrics) {
  const nsToMs = (ns) => {
    return Number(ns) / 1000000
  }

  return {
    totalTimeMs: nsToMs(metrics.endTime - metrics.startTime),
    steps: {
      inputValidation: metrics.steps.inputValidationEnd
        ? nsToMs(
            metrics.steps.inputValidationEnd -
              metrics.steps.inputValidationStart
          )
        : 0,
      nonceRetrieval: metrics.steps.nonceRetrievalEnd
        ? nsToMs(
            metrics.steps.nonceRetrievalEnd - metrics.steps.nonceRetrievalStart
          )
        : 0,
      clientSetup: metrics.steps.clientSetupEnd
        ? nsToMs(metrics.steps.clientSetupEnd - metrics.steps.clientSetupStart)
        : 0,
      presentationValidation: metrics.steps.presentationValidationEnd
        ? nsToMs(
            metrics.steps.presentationValidationEnd -
              metrics.steps.presentationValidationStart
          )
        : 0,
      credentialValidation: metrics.steps.credentialValidationEnd
        ? nsToMs(
            metrics.steps.credentialValidationEnd -
              metrics.steps.credentialValidationStart
          )
        : 0
    },
    success: metrics.success,
    error: metrics.error
  }
}
