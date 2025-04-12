const {
  IotaDocument,
  IotaIdentityClient,
  JwkMemStore,
  JwsAlgorithm,
  MethodScope
} = require('@iota/identity-wasm/node')
const { Utils, SecretManager } = require('@iota/sdk-wasm/node')
const { ensureAddressHasFunds } = require('./wallet.js')

/**
  Creates a DID Document and publishes it in a new Alias Output.
*/
async function createDid(client, secretManager, storage) {
  const didClient = new IotaIdentityClient(client)
  const networkHrp = await didClient.getNetworkHrp()

  const secretManagerInstance = new SecretManager(secretManager)
  const addresses = await secretManagerInstance.generateEd25519Addresses({
    accountIndex: 0,
    range: { start: 0, end: 1 },
    bech32Hrp: networkHrp
  })

  const walletAddressBech32 = addresses[0]
  console.log('Wallet address Bech32:', walletAddressBech32)

  await ensureAddressHasFunds(client, walletAddressBech32)

  const address = Utils.parseBech32Address(walletAddressBech32)

  const document = new IotaDocument(networkHrp)

  const fragment = await document.generateMethod(
    storage,
    JwkMemStore.ed25519KeyType(),
    JwsAlgorithm.EdDSA,
    '#jwk',
    MethodScope.AssertionMethod()
  )

  const aliasOutput = await didClient.newDidOutput(address, document)

  const published = await didClient.publishDidOutput(secretManager, aliasOutput)

  return { address, document: published, fragment }
}

module.exports = {
  createDid
}
