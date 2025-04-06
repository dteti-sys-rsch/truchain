const router = require('express').Router()

const { initConnection, createVP, verifyVP } = require('../controllers/identity')

router.post('/init/:id', initConnection)
router.post('/create', createVP)
router.post('/verify', verifyVP)

module.exports = router
