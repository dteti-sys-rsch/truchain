const mongoose = require('mongoose')
const Schema = mongoose.Schema

const verifiedBankSchema = new Schema(
  {
    legalName: {
      type: String,
      required: true
    },
    registrationNumber: {
      type: String,
      required: true
    },
    entityType: {
      type: String,
      required: true
    },
    jurisdiction: {
      type: String,
      required: true
    },
    issueDate: {
      type: String,
      required: true
    },
    expirationDate: {
      type: String,
      required: true
    }
  },
  {
    timestamps: true
  }
)

module.exports = mongoose.model('VerifiedBank', verifiedBankSchema)
