const router = require('express').Router()

const { createVC } = require('../controllers/data')

router.post('/sign', createVC)

module.exports = router
