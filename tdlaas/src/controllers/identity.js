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

const client = new Client({ primaryNode: process.env.API_ENDPOINT, localPow: true });
const didClient = new IotaIdentityClient(client);
const resolver = new Resolver({ client: didClient });

const jwsVerifier = new EdDSAJwsVerifier();
const credentialValidator = new JwtCredentialValidator(jwsVerifier);

const { SHA256 } = require('crypto-js')
const { Client: SDKClient, utf8ToHex, hexToUtf8 } = require('@iota/sdk')
const Transaction = require('../models/transaction')

const sdkClient = new SDKClient({
  primaryNode: process.env.API_ENDPOINT,
  localPow: true
})

exports.initConnection = async (req, res) => {
  const { id } = req.params
  const nonce = crypto.randomBytes(16).toString('hex')

  redisClient
    // .set(`id:${id}`, nonce, { EX: 300 })
    .set(`id:${id}`, nonce)
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
    // await redisClient.del(`id:${uniqueId}`)

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

exports.verifyVPV2 = async (req, res) => {
  try {
    const { presentationJwt, uniqueId } = req.body

    if (!presentationJwt || !uniqueId) {
      throw new Error(
        'Missing required parameters: presentationJwt and uniqueId'
      )
    }

    // --- Fetch nonce from Redis ---
    const nonce = await redisClient.get(`id:${uniqueId}`)
    if (!nonce) {
      throw new Error('Invalid or expired nonce')
    }

    // --- Decode VP JWT ---
    const jwtObject = new Jwt(presentationJwt)
    const presentationHolderDID = JwtPresentationValidator.extractHolder(jwtObject)

    // --- Resolve Holder DID (with cache) ---
    const holderCacheKey = `did:${presentationHolderDID}`
    let resolvedHolder = await redisClient.get(holderCacheKey)
    if (resolvedHolder) {
      resolvedHolder = JSON.parse(resolvedHolder)
    } else {
      resolvedHolder = await resolver.resolve(presentationHolderDID.toString())
      await redisClient.set(holderCacheKey, JSON.stringify(resolvedHolder), 'EX', 300)
    }

    // --- Validate Presentation ---
    const jwtPresentationValidationOptions = new JwtPresentationValidationOptions({
      presentationVerifierOptions: new JwsVerificationOptions({ nonce })
    })
    const decodedPresentation = new JwtPresentationValidator(
      new EdDSAJwsVerifier()
    ).validate(jwtObject, resolvedHolder, jwtPresentationValidationOptions)

    // --- Extract and process credentials ---
    const jwtCredentials = decodedPresentation
      .presentation()
      .verifiableCredential()
      .map((credential) => {
        const jwt = credential.tryIntoJwt()
        if (!jwt) throw new Error('Expected a JWT credential')
        return jwt
      })

    // --- Resolve all issuers in parallel with cache ---
    const resolvedIssuers = await Promise.all(
      jwtCredentials.map(async (jwtCredential) => {
        const issuerDID = JwtCredentialValidator.extractIssuerFromJwt(jwtCredential).toString()
        const cacheKey = `did:${issuerDID}`
        let cached = await redisClient.get(cacheKey)
        if (cached) return JSON.parse(cached)
        const resolved = await resolver.resolve(issuerDID)
        await redisClient.set(cacheKey, JSON.stringify(resolved), 'EX', 300)
        return resolved
      })
    )

    // --- Validate credentials in parallel ---
    const credentialValidator = new JwtCredentialValidator(new EdDSAJwsVerifier())
    const validationOptions = new JwtCredentialValidationOptions({
      subjectHolderRelationship: [
        presentationHolderDID.toString(),
        SubjectHolderRelationship.AlwaysSubject
      ]
    })

    const credentialValidations = await Promise.all(
      jwtCredentials.map((jwt, i) =>
        credentialValidator
          .validate(jwt, resolvedIssuers[i], validationOptions, FailFast.FirstError)
          .then(v => v.intoCredential())
      )
    )

    // --- Send response ---
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

exports.l1andl2 = async (req, res) => {
  try {
    const {
      issuerDid,
      timestamp,
      fromBank,
      fromAccount,
      toBank,
      toAccount,
      amountReceived,
      receivingCurrency,
      amountPaid,
      paymentCurrency,
      paymentFormat
    } = req.body

    if (
      !issuerDid ||
      !timestamp ||
      !fromBank ||
      !fromAccount ||
      !toBank ||
      !toAccount ||
      !amountReceived ||
      !receivingCurrency ||
      !amountPaid ||
      !paymentCurrency ||
      !paymentFormat
    ) {
      return res.status(400).json({
        message: 'Missing required parameters'
      })
    }

    if (!issuerDid.startsWith('did:iota:')) {
      return res.status(400).json({
        message: 'Invalid DID format'
      })
    }

    if (
      !timestamp.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/)
    ) {
      return res.status(400).json({
        message: 'Invalid timestamp format'
      })
    }

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

    try {
      const transactionData = {
      issuerDid,
      timestamp,
      fromBank,
      fromAccount,
      toBank,
      toAccount,
      amountReceived,
      receivingCurrency,
      amountPaid,
      paymentCurrency,
      paymentFormat
    }

    const dataHash = SHA256(JSON.stringify(transactionData)).toString()

    const secretManager = { mnemonic: process.env.TEST_MNEMONIC_1 }
    const options = {
      tag: utf8ToHex('TDLAAS'),
      data: utf8ToHex(dataHash)
    }

    const block = await sdkClient.buildAndPostBlock(secretManager, options)

    const savedTransaction = await Transaction.create({
      iotaBlockId: block[0],
      ...transactionData
    })

    res.status(200).json({
      message: 'Data stored successfully',
      iota: {
        rawBlock: block[0],
        blockId: block.blockId
      }
    })
    } catch (error) {
      console.error('Error storing data:', error)
      res.status(500).json({
      message: 'Failed to store data',
      error: error.message
    })
    }
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
