const mongoose = require('mongoose')
const Schema = mongoose.Schema

const transactionSchema = new Schema(
  {
    iotaBlockId: {
      type: String,
      required: true
    },
    issuerDid: {
      type: String,
      required: true
    },
    timestamp: {
      type: String,
      required: true
    },
    fromBank: {
      type: String,
      required: true
    },
    fromAccount: {
      type: String,
      required: true
    },
    toBank: {
      type: String,
      required: true
    },
    toAccount: {
      type: String,
      required: true
    },
    amountReceived: {
      type: Number,
      required: true
    },
    receivingCurrency: {
      type: String,
      required: true
    },
    amountPaid: {
      type: Number,
      required: true
    },
    paymentCurrency: {
      type: String,
      required: true
    },
    paymentFormat: {
      type: String,
      required: true
    }
  },
  {
    timestamps: true
  }
)

module.exports = mongoose.model('Transaction', transactionSchema)
