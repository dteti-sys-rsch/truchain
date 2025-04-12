const router = require('express').Router()

const { createVC } = require('../controllers/identity')

router.post('/vc/create', createVC)

module.exports = router
