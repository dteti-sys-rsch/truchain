const router = require('express').Router()

const { initConnection, verifyVP } = require('../controllers/identity')

router.post('/init/:id', initConnection)
router.post('/verify', verifyVP)

module.exports = router
