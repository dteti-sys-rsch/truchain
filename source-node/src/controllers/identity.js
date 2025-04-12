const {
  JwkMemStore,
  KeyIdMemStore,
  Storage
} = require('@iota/identity-wasm/node')
const { Client } = require('@iota/sdk-wasm/node')
const { createDid } = require('../utils/did')

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

  console.log('Holder DID:', holderDID)

  res.status(200).json({
    message: 'DID created successfully',
    did: holderDID.holderDocument
  })
}
