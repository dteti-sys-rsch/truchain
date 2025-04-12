const router = require('express').Router()

const { createHolderDID } = require('../controllers/identity')

router.post('/did/create', createHolderDID)

module.exports = router
