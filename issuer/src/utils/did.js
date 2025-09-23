const {
  JwkMemStore,
  KeyIdMemStore,
  Storage,
  IotaDocument,
  IotaIdentityClient,
  JwsAlgorithm,
  MethodScope
} = require('@iota/identity-wasm/node')
const { Utils, SecretManager } = require('@iota/sdk-wasm/node')
const { ensureAddressHasFunds } = require('./wallet.js')

const persistentStorage = new Storage(new JwkMemStore(), new KeyIdMemStore())
let didCache = null

async function createDid(client, secretManager) {
  if (didCache) {
    console.log('Using cached DID')
    return didCache
  }

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
    persistentStorage,
    JwkMemStore.ed25519KeyType(),
    JwsAlgorithm.EdDSA,
    '#jwk',
    MethodScope.AssertionMethod()
  )

  const aliasOutput = await didClient.newDidOutput(address, document)
  const published = await didClient.publishDidOutput(secretManager, aliasOutput)

  didCache = {
    address,
    document: published,
    fragment,
    storage: persistentStorage
  }

  return didCache
}

function getDid() {
  if (!didCache) throw new Error('DID not created yet')
  return didCache
}

function clearDidCache() {
  didCache = null
}

module.exports = { createDid, getDid, clearDidCache }
