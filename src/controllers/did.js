const { Client } = require('@iota/sdk-wasm/node')
const {
  JwkMemStore,
  KeyIdMemStore,
  Storage
} = require('@iota/identity-wasm/node')

const { createDid } = require('../utils/did.js')

exports.createDid = async (req, res) => {
  try {
    const client = new Client({
      primaryNode: process.env.API_ENDPOINT,
      localPow: true
    })

    const secretManager = {
      mnemonic: process.env.MNEMONIC
    }

    const storage = new Storage(new JwkMemStore(), new KeyIdMemStore())

    const { address, document, fragment } = await createDid(
      client,
      secretManager,
      storage
    )

    res.status(200).json({
      address: address.toString(),
      document: document.toString(),
      fragment
    })
  } catch (error) {
    console.error('Failed to create DID:', error)
    res.status(500).json({
      error: 'Failed to create DID',
      details: error.message || error
    })
  }
}
