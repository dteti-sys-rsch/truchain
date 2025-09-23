const crypto = require('crypto')
const Transaction = require('../models/transaction')

// Simulate external fraud check (e.g., OpenBanking risk engine)
// Real-time fraud detection systems process transactions in milliseconds.
// Deep learning models have an average fraud detection latency of 80ms. 
// Source: ResearchGate (https://www.researchgate.net/figure/Fraud-Detection-Latency-of-AI-ML-Models-This-is-an-average-time-in-milliseconds-of-the_fig2_388314352)
async function simulateExternalCheck() {
  return new Promise((resolve) => setTimeout(resolve, 40 + Math.random() * 30)) // 40–70ms
}

// Simulate DB latency
// Cloud databases like Azure Cosmos DB guarantee write latencies below 10ms at the 99th percentile.
// Source: Azure Cosmos DB Documentation (https://en.wikipedia.org/wiki/Cosmos_DB)
async function simulateDBWrite(transaction) {
  return new Promise((resolve) => {
    setTimeout(async () => {
      const saved = await transaction.save()
      resolve(saved)
    }, 20 + Math.random() * 10) // 20–30ms
  })
}

// Basic validator
function validateInput(body) {
  const required = [
    'timestamp',
    'fromBank',
    'fromAccount',
    'toBank',
    'toAccount',
    'amountReceived',
    'receivingCurrency',
    'amountPaid',
    'paymentCurrency',
    'paymentFormat'
  ]

  const missing = required.filter((key) => !body[key])
  return {
    valid: missing.length === 0,
    errors: missing
  }
}

exports.createTransaction = async (req, res) => {
  const startTime = Date.now()

  // Simulate auth token parsing / API key
  const apiKey = req.headers['x-api-key']
  console.log('API Key:', apiKey)
  console.log('API Key from env:', process.env.MOCK_API_KEY)
  if (!apiKey || apiKey !== process.env.MOCK_API_KEY) {
    return res
      .status(401)
      .json({ error: 'Unauthorized: invalid or missing API key' })
  }

  // Input validation
  const { valid, errors } = validateInput(req.body)
  if (!valid) {
    return res.status(400).json({
      error: 'Invalid input',
      missingFields: errors
    })
  }

  // Simulate external dependency (e.g., fraud, AML, etc.)
  await simulateExternalCheck()

  const {
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

  const newTransaction = new Transaction({
    timestamp: new Date(timestamp),
    fromBank: fromBank.trim(),
    fromAccount: fromAccount.trim(),
    toBank: toBank.trim(),
    toAccount: toAccount.trim(),
    amountReceived: parseFloat(amountReceived),
    receivingCurrency: receivingCurrency.toUpperCase(),
    amountPaid: parseFloat(amountPaid),
    paymentCurrency: paymentCurrency.toUpperCase(),
    paymentFormat: paymentFormat.trim(),
    idempotencyKey: crypto.randomUUID()
  })

  try {
    const savedTransaction = await simulateDBWrite(newTransaction)
    const totalTime = Date.now() - startTime

    res.status(201).json({
      transaction: savedTransaction,
      meta: {
        processingTimeMs: totalTime
      }
    })
  } catch (error) {
    console.error('Transaction save failed', error)
    res.status(500).json({ error: 'Error saving transaction' })
  }
}

// Simulate external fraud check (e.g., OpenBanking risk engine)
// Real-time fraud detection systems process transactions in milliseconds.
// Deep learning models have an average fraud detection latency of 80ms. 
// Source: ResearchGate (https://www.researchgate.net/figure/Fraud-Detection-Latency-of-AI-ML-Models-This-is-an-average-time-in-milliseconds-of-the_fig2_388314352)
// async function simulateExternalCheck() {
//   return new Promise((resolve) => setTimeout(resolve, 40 + Math.random() * 30)) // 40–70ms
// }

// Simulate DB read latency
// Cloud databases like FaunaDB report average read latencies of 11ms.
// Source: Fauna Blog (https://fauna.com/blog/real-world-database-latency)
async function simulateDBRead() {
  return new Promise((resolve) => setTimeout(resolve, 11 + Math.random() * 9)) // 11–20ms
}

// Query transactions with simulated latency
exports.queryTransactions = async (req, res) => {
  const startTime = Date.now()

  // Simulate auth token parsing / API key
  const apiKey = req.headers['x-api-key']
  if (!apiKey || apiKey !== process.env.MOCK_API_KEY) {
    return res
      .status(401)
      .json({ error: 'Unauthorized: invalid or missing API key' })
  }

  // Simulate external dependency (e.g., fraud, AML, etc.)
  await simulateExternalCheck()

  // Simulate DB read latency
  await simulateDBRead()

  try {
    const transactions = await Transaction.find({})
    const totalTime = Date.now() - startTime

    res.status(200).json({
      transactions,
      meta: {
        processingTimeMs: totalTime
      }
    })
  } catch (error) {
    console.error('Transaction query failed', error)
    res.status(500).json({ error: 'Error querying transactions' })
  }
}
