const {
  JwkMemStore,
  KeyIdMemStore,
  Storage,
  JwsSignatureOptions,
  JwtPresentationOptions,
  Presentation
} = require('@iota/identity-wasm/node')
const { Client } = require('@iota/sdk-wasm/node')
const { createDid } = require('../utils/did')
const axios = require('axios')

const client = new Client({
  primaryNode: process.env.API_ENDPOINT,
  localPow: true
})

async function createHolderDID() {
  try {
    const holderSecretManager = { mnemonic: process.env.HOLDER_MNEMONIC }
    const holderStorage = new Storage(new JwkMemStore(), new KeyIdMemStore())
    const { document: holderDocument, fragment: holderFragment } =
      await createDid(client, holderSecretManager, holderStorage)

    return {
      holderDocument,
      holderFragment,
      holderStorage
    }
  } catch (error) {
    console.error('Error creating DID:', error)
    throw new Error('Failed to creat Holder DID: ' + error.message)
  }
}

exports.createHolderDID = async (req, res) => {
  const holderDID = await createHolderDID()

  res.status(200).json({
    message: 'DID created successfully',
    did: holderDID.holderDocument
  })
}

exports.createVP = async (req, res) => {
  try {
    const { uniqueId, credentialJwt } = req.body

    const nonceResponse = await axios.post(
      `${process.env.VERIFIER_ENDPOINT}/api/identity/init/${uniqueId}`
    )
    const nonce = nonceResponse.data.nonce

    const holderDID = await createHolderDID()

    const unsignedVp = new Presentation({
      holder: holderDID.holderDocument.id(),
      verifiableCredential: [credentialJwt]
    })

    const presentationJwt =
      await holderDID.holderDocument.createPresentationJwt(
        holderDID.holderStorage,
        holderDID.holderFragment,
        unsignedVp,
        new JwsSignatureOptions({ nonce }),
        new JwtPresentationOptions({
          expirationDate: new Date(Date.now() + 3600 * 1000)
        })
      )

    res.status(200).json({
      presentationJwt: presentationJwt.toString(),
      nonce,
      vp: unsignedVp.toJSON()
    })
  } catch (error) {
    console.error('Error creating verifiable presentation:', error)

    if (error.response) {
      console.error('Server responded with:', error.response.status)
      console.error('Response data:', error.response.data)
      res.status(error.response.status || 500).json({
        error: 'Verifier error',
        details: error.response.data
      })
    } else if (error.request) {
      console.error('No response received:', error.request)
      res.status(503).json({ error: 'Verifier unavailable' })
    } else {
      console.error('Request setup error:', error.message)
      res.status(500).json({ error: 'Internal server error' })
    }
  }
}
