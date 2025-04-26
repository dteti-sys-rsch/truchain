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

exports.verifyVC = async (req, res) => {
  try {
    const { credentialJwt } = req.body

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

    res.status(200).json({
      message: 'VC verified successfully',
      credential: JSON.parse(decoded_credential.intoCredential(), null, 2)
    })
  } catch (error) {
    console.error('Error verifying VC:', error)
    res.status(500).json({
      message: 'Failed to verify VC',
      error: error.message
    })
  }
}

exports.storeData = async (req, res) => {
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
