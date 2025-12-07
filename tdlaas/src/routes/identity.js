const router = require('express').Router()

const { initConnection, verifyVP, verifyVPV2, l1andl2 } = require('../controllers/identity')

router.post('/init/:id', initConnection)
router.post('/verify', verifyVP)
router.post('/verifyv2', verifyVPV2)
router.post('/l1andl2', l1andl2)

module.exports = router
