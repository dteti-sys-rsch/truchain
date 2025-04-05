const router = require('express').Router()

const { createDid } = require('../controllers/did')

router.post('/create', createDid)

module.exports = router
