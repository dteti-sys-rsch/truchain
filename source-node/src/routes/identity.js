const router = require('express').Router()

const { createHolderDID, createVP } = require('../controllers/identity')

router.post('/did/create', createHolderDID)
router.post('/vp/create', createVP)

module.exports = router
