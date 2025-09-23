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
const { Client: SDKClient, utf8ToHex, hexToUtf8 } = require('@iota/sdk')
const { SHA256 } = require('crypto-js')
const Transaction = require('../models/transaction')

const client = new Client({
  primaryNode: process.env.API_ENDPOINT,
  localPow: true
})

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

exports.endToEnd = async (req, res) => {
  try {
    const { presentationJwt, uniqueId, credentialJwt } = req.body

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
    //   await redisClient.del(`id:${uniqueId}`)

    // Verify the VC
    const jwtObj = new Jwt(credentialJwt)

    const holderDID = JwtCredentialValidator.extractIssuerFromJwt(jwtObj)
    const didDocument = await resolver.resolve(holderDID.toString())

    const decoded_credential = new JwtCredentialValidator(
      new EdDSAJwsVerifier()
    ).validate(
      jwtObj,
      didDocument,
      new JwtCredentialValidationOptions(),
      FailFast.FirstError
    )

    const credential = JSON.parse(decoded_credential.intoCredential(), null, 2)

    console.log('Decoded credential:', credential)
    const transactionsWithIssuer =
      credential.credentialSubject.transactions.map((tx) => ({
        ...tx,
        issuerDid: credential.issuer
      }))

    const dataHash = SHA256(
      JSON.stringify(transactionsWithIssuer[0])
    ).toString()

    const secretManager = { mnemonic: process.env.TEST_MNEMONIC_1 }
    const options = {
      tag: utf8ToHex('TDLAAS'),
      data: utf8ToHex(dataHash)
    }

    const block = await sdkClient.buildAndPostBlock(secretManager, options)

    const savedTransaction = await Transaction.create({
      iotaBlockId: block[0],
      ...transactionsWithIssuer[0]
    })

    res.status(200).json({
      message: 'Data stored successfully',
      iota: {
        rawBlock: block[0],
        blockId: block.blockId
      }
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

exports.endToEndProd = async (req, res) => {
  try {
    const { credentialJwt } = req.body

    // Verify the VC
    const jwtObj = new Jwt(credentialJwt)
    const didClient = new IotaIdentityClient(client)
    const resolver = new Resolver({ client: didClient })

    const holderDID = JwtCredentialValidator.extractIssuerFromJwt(jwtObj)
    const didDocument = await resolver.resolve(holderDID.toString())

    const decoded_credential = new JwtCredentialValidator(
      new EdDSAJwsVerifier()
    ).validate(
      jwtObj,
      didDocument,
      new JwtCredentialValidationOptions(),
      FailFast.FirstError
    )

    const credential = JSON.parse(decoded_credential.intoCredential(), null, 2)

    const transactionsWithIssuer =
      credential.credentialSubject.transactions.map((tx) => ({
        ...tx,
        issuerDid: credential.issuer
      }))

    const dataHash = SHA256(
      JSON.stringify(transactionsWithIssuer[0])
    ).toString()

    const secretManager = { mnemonic: process.env.TEST_MNEMONIC_1 }
    const options = {
      tag: utf8ToHex('TDLAAS'),
      data: utf8ToHex(dataHash)
    }

    const block = await sdkClient.buildAndPostBlock(secretManager, options)

    const savedTransaction = await Transaction.create({
      iotaBlockId: block[0],
      ...transactionsWithIssuer[0]
    })

    res.status(200).json({
      message: 'Data stored successfully',
      iota: {
        rawBlock: block[0],
        blockId: block.blockId
      }
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
