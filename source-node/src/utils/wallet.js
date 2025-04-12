const fetch = require('node-fetch')

/*
  Checks if address has funds. If not, requests from faucet.
*/
async function ensureAddressHasFunds(client, addressBech32) {
  let balance = await getAddressBalance(client, addressBech32)
  if (balance > BigInt(0)) return

  await requestFundsFromFaucet(addressBech32)

  for (let i = 0; i < 9; i++) {
    await new Promise((f) => setTimeout(f, 5000))
    balance = await getAddressBalance(client, addressBech32)
    if (balance > BigInt(0)) break
  }
}

/*
  Returns the balance of the given address.
*/
async function getAddressBalance(client, addressBech32) {
  const outputIds = await client.basicOutputIds([
    { address: addressBech32 },
    { hasExpiration: false },
    { hasTimelock: false },
    { hasStorageDepositReturn: false }
  ])

  const outputs = await client.getOutputs(outputIds.items)
  let totalAmount = BigInt(0)

  for (const output of outputs) {
    totalAmount += output.output.getAmount()
  }

  return totalAmount
}

/*
  Requests tokens from the local faucet API.
*/
async function requestFundsFromFaucet(addressBech32) {
  const requestObj = JSON.stringify({ address: addressBech32 })

  try {
    const response = await fetch(process.env.FAUCET_ENDPOINT, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json'
      },
      body: requestObj
    })

    if (response.status === 202) return
    if (response.status === 429)
      throw new Error('Too many requests. Try again later.')

    const data = await response.json()
    throw new Error(data.error?.message || 'Unknown faucet error.')
  } catch (error) {
    throw new Error(`Failed to get funds from faucet: ${error}`)
  }
}

module.exports = {
  ensureAddressHasFunds,
  getAddressBalance,
  requestFundsFromFaucet
}
