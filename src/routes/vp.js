const router = require('express').Router()

const { createVP, fullVPCode } = require('../controllers/vp')

router.post('/create', createVP)
// router.post('/verify', verifyVP)
router.post('/full', fullVPCode)

module.exports = router
