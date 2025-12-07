const router = require('express').Router()

const { createHolderDID, createVP } = require('../controllers/identity')
const { generateMnemonic } = require('../utils/mnemonic')

router.post('/did/create', createHolderDID)
router.post('/vp/create', createVP)

router.post('/mnemonic', generateMnemonic)

module.exports = router
