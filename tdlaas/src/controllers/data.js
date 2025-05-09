const {
  EdDSAJwsVerifier,
  FailFast,
  JwtCredentialValidationOptions,
  JwtCredentialValidator,
  IotaIdentityClient,
  Resolver,
  Jwt
} = require('@iota/identity-wasm/node')
const { Client } = require('@iota/sdk-wasm/node')
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

/*
  L2 Architecture
*/
function verifyTransactionData(credentialSubject) {
  // Check if transactions array exists
  if (
    !credentialSubject.transactions ||
    !Array.isArray(credentialSubject.transactions)
  ) {
    throw new Error(
      'Missing or invalid transactions array in credential subject'
    )
  }

  // Validate each transaction in the array
  credentialSubject.transactions.forEach((transaction, index) => {
    validateSingleTransaction(transaction, index)
  })
}

function validateSingleTransaction(transaction, index) {
  const requiredFields = {
    timestamp: 'string',
    fromBank: 'string',
    fromAccount: 'string',
    toBank: 'string',
    toAccount: 'string',
    amountReceived: 'number',
    receivingCurrency: 'string',
    amountPaid: 'number',
    paymentCurrency: 'string',
    paymentFormat: 'string'
  }

  // Check if all required fields exist
  for (const [field, type] of Object.entries(requiredFields)) {
    if (!(field in transaction)) {
      throw new Error(`Transaction ${index}: Missing required field: ${field}`)
    }

    // Verify field types
    if (typeof transaction[field] !== type) {
      throw new Error(
        `Transaction ${index}: Invalid type for ${field}. Expected ${type}, got ${typeof transaction[
          field
        ]}`
      )
    }
  }

  // Additional validation for timestamp format
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(transaction.timestamp)) {
    throw new Error(
      `Transaction ${index}: Invalid timestamp format. Expected ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)`
    )
  }

  // Validate currency codes (simple check)
  const validCurrencies = ['USD', 'IDR', 'EUR', 'GBP'] // Add more as needed
  if (!validCurrencies.includes(transaction.receivingCurrency)) {
    throw new Error(
      `Transaction ${index}: Invalid receiving currency: ${transaction.receivingCurrency}`
    )
  }
  if (!validCurrencies.includes(transaction.paymentCurrency)) {
    throw new Error(
      `Transaction ${index}: Invalid payment currency: ${transaction.paymentCurrency}`
    )
  }

  // Validate payment formats
  const validFormats = ['Bank Transfer', 'Card Payment', 'Digital Wallet']
  if (!validFormats.includes(transaction.paymentFormat)) {
    throw new Error(
      `Transaction ${index}: Invalid payment format: ${transaction.paymentFormat}`
    )
  }

  // Validate amounts are positive numbers
  if (transaction.amountReceived <= 0) {
    throw new Error(
      `Transaction ${index}: amountReceived must be a positive number`
    )
  }
  if (transaction.amountPaid <= 0) {
    throw new Error(
      `Transaction ${index}: amountPaid must be a positive number`
    )
  }
}

exports.verifyVC = async (req, res) => {
  const metrics = {
    startTime: process.hrtime.bigint(),
    steps: {},
    success: false,
    error: null
  }

  try {
    const { credentialJwt } = req.body

    // Step 1: Input validation
    metrics.steps.inputValidationStart = process.hrtime.bigint()
    if (!credentialJwt) {
      throw new Error('Missing required parameter: credentialJwt')
    }
    metrics.steps.inputValidationEnd = process.hrtime.bigint()

    // Step 2: JWT parsing
    metrics.steps.jwtParsingStart = process.hrtime.bigint()
    const jwtObj = new Jwt(credentialJwt)
    metrics.steps.jwtParsingEnd = process.hrtime.bigint()

    // Step 3: DID Client setup
    metrics.steps.clientSetupStart = process.hrtime.bigint()
    const didClient = new IotaIdentityClient(client)
    const resolver = new Resolver({ client: didClient })
    metrics.steps.clientSetupEnd = process.hrtime.bigint()

    // Step 4: DID Resolution
    metrics.steps.didResolutionStart = process.hrtime.bigint()
    const holderDID = JwtCredentialValidator.extractIssuerFromJwt(jwtObj)
    const didDocument = await resolver.resolve(holderDID.toString())
    metrics.steps.didResolutionEnd = process.hrtime.bigint()

    // Step 5: VC Validation
    metrics.steps.vcValidationStart = process.hrtime.bigint()
    const decoded_credential = new JwtCredentialValidator(
      new EdDSAJwsVerifier()
    ).validate(
      jwtObj,
      didDocument,
      new JwtCredentialValidationOptions(),
      FailFast.FirstError
    )
    metrics.steps.vcValidationEnd = process.hrtime.bigint()

    // Convert to credential object
    const credential = JSON.parse(decoded_credential.intoCredential())

    // Step 6: Verify required transaction data structure
    metrics.steps.dataValidationStart = process.hrtime.bigint()
    verifyTransactionData(credential.credentialSubject)
    metrics.steps.dataValidationEnd = process.hrtime.bigint()

    metrics.endTime = process.hrtime.bigint()
    metrics.success = true

    // Calculate durations
    const durations = calculateVCDurations(metrics)

    res.status(200).json({
      message: 'VC verified successfully',
      credential: credential,
      metrics: durations
    })
  } catch (error) {
    metrics.endTime = process.hrtime.bigint()
    metrics.error = error.message

    console.error('Error verifying VC:', error)
    res.status(500).json({
      message: 'Failed to verify VC',
      error: error.message,
      metrics: calculateVCDurations(metrics)
    })
  }
}

function calculateVCDurations(metrics) {
  const nsToMs = (ns) => Number(ns) / 1000000

  return {
    totalTimeMs: nsToMs(metrics.endTime - metrics.startTime),
    steps: {
      inputValidation: metrics.steps.inputValidationEnd
        ? nsToMs(
            metrics.steps.inputValidationEnd -
              metrics.steps.inputValidationStart
          )
        : 0,
      jwtParsing: metrics.steps.jwtParsingEnd
        ? nsToMs(metrics.steps.jwtParsingEnd - metrics.steps.jwtParsingStart)
        : 0,
      clientSetup: metrics.steps.clientSetupEnd
        ? nsToMs(metrics.steps.clientSetupEnd - metrics.steps.clientSetupStart)
        : 0,
      didResolution: metrics.steps.didResolutionEnd
        ? nsToMs(
            metrics.steps.didResolutionEnd - metrics.steps.didResolutionStart
          )
        : 0,
      vcValidation: metrics.steps.vcValidationEnd
        ? nsToMs(
            metrics.steps.vcValidationEnd - metrics.steps.vcValidationStart
          )
        : 0,
      dataValidation: metrics.steps.dataValidationEnd
        ? nsToMs(
            metrics.steps.dataValidationEnd - metrics.steps.dataValidationStart
          )
        : 0
    },
    success: metrics.success,
    error: metrics.error
  }
}

/*
  L3 Architecture
*/
exports.storeData = async (req, res) => {
  const metrics = {
    startTime: process.hrtime.bigint(),
    steps: {},
    success: false,
    error: null
  }

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

    // Step 3: Generate data hash
    metrics.steps.hashGenerationStart = process.hrtime.bigint()
    const dataHash = SHA256(JSON.stringify(transactionData)).toString()
    metrics.steps.hashGenerationEnd = process.hrtime.bigint()

    // Step 4: Prepare IOTA block
    metrics.steps.iotaPreparationStart = process.hrtime.bigint()
    const secretManager = { mnemonic: process.env.TEST_MNEMONIC_1 }
    const options = {
      tag: utf8ToHex('TDLAAS'),
      data: utf8ToHex(dataHash)
    }
    metrics.steps.iotaPreparationEnd = process.hrtime.bigint()

    // Step 5: Post to IOTA Tangle
    metrics.steps.iotaPostStart = process.hrtime.bigint()
    const block = await sdkClient.buildAndPostBlock(secretManager, options)
    metrics.steps.iotaPostEnd = process.hrtime.bigint()

    // Step 6: Store in database
    metrics.steps.dbStorageStart = process.hrtime.bigint()
    const savedTransaction = await Transaction.create({
      iotaBlockId: block[0],
      ...transactionData
    })
    metrics.steps.dbStorageEnd = process.hrtime.bigint()

    metrics.endTime = process.hrtime.bigint()
    metrics.success = true

    // Calculate durations
    const durations = calculateStorageDurations(metrics)

    res.status(200).json({
      message: 'Data stored successfully',
      transaction: savedTransaction,
      iota: {
        rawBlock: block[0],
        blockId: block.blockId
      },
      metrics: durations
    })
  } catch (error) {
    metrics.endTime = process.hrtime.bigint()
    metrics.error = error.message

    console.error('Error storing data:', error)
    res.status(500).json({
      message: 'Failed to store data',
      error: error.message,
      metrics: calculateStorageDurations(metrics)
    })
  }
}

function calculateStorageDurations(metrics) {
  const nsToMs = (ns) => Number(ns) / 1000000

  return {
    totalTimeMs: nsToMs(metrics.endTime - metrics.startTime),
    steps: {
      hashGeneration: metrics.steps.hashGenerationEnd
        ? nsToMs(
            metrics.steps.hashGenerationEnd - metrics.steps.hashGenerationStart
          )
        : 0,
      iotaPreparation: metrics.steps.iotaPreparationEnd
        ? nsToMs(
            metrics.steps.iotaPreparationEnd -
              metrics.steps.iotaPreparationStart
          )
        : 0,
      iotaPost: metrics.steps.iotaPostEnd
        ? nsToMs(metrics.steps.iotaPostEnd - metrics.steps.iotaPostStart)
        : 0,
      dbStorage: metrics.steps.dbStorageEnd
        ? nsToMs(metrics.steps.dbStorageEnd - metrics.steps.dbStorageStart)
        : 0
    },
    success: metrics.success,
    error: metrics.error
  }
}

exports.queryData = async (req, res) => {
  try {
    const { blockId } = req.query

    const block = await sdkClient.getBlock(blockId)
    const hashed = hexToUtf8(block.payload.data)

    const transaction = await Transaction.findOne({
      iotaBlockId: blockId
    })

    if (!transaction) {
      return res.status(404).json({
        message: 'Transaction not found'
      })
    }

    const transactionData = {
      issuerDid: transaction.issuerDid,
      timestamp: transaction.timestamp,
      fromBank: transaction.fromBank,
      fromAccount: transaction.fromAccount,
      toBank: transaction.toBank,
      toAccount: transaction.toAccount,
      amountReceived: transaction.amountReceived,
      receivingCurrency: transaction.receivingCurrency,
      amountPaid: transaction.amountPaid,
      paymentCurrency: transaction.paymentCurrency,
      paymentFormat: transaction.paymentFormat
    }

    const dataHash = SHA256(JSON.stringify(transactionData)).toString()

    if (hashed !== dataHash) {
      return res.status(400).json({
        message: 'Data hash mismatch'
      })
    }

    res.status(200).json({
      message: 'Data queried successfully',
      transaction: {
        iotaBlockId: blockId,
        ...transactionData
      }
    })
  } catch (error) {
    console.error('Error querying data:', error)
    res.status(500).json({
      message: 'Failed to query data',
      error: error.message
    })
  }
}
