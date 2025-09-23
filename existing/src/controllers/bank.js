const VerifiedBank = require('../models/verified-bank')

exports.createVerifiedBank = async (req, res) => {
  const metrics = {
    startTime: process.hrtime.bigint(),
    steps: {},
    success: false,
    error: null
  }

  const {
    legalName,
    registrationNumber,
    entityType,
    jurisdiction,
    issueDate,
    expirationDate
  } = req.body

  const newVerifiedBank = new VerifiedBank({
    legalName,
    registrationNumber,
    entityType,
    jurisdiction,
    issueDate,
    expirationDate
  })

  try {
    const savedVerifiedBank = await newVerifiedBank.save()
    res.status(201).json(savedVerifiedBank)
  } catch (error) {
    res.status(500).json({ error: 'Error saving verified bank' })
  }
}
