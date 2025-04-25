const router = require('express').Router()

const { verifyVC } = require('../controllers/data')

router.post('/verify', verifyVC)

module.exports = router
