const router = require('express').Router()

const { createVC } = require('../controllers/vc')

router.post('/create', createVC)

module.exports = router
