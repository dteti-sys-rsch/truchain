const router = require('express').Router()

const { createVC } = require('../controllers/identity')

router.post('/create', createVC)

module.exports = router
