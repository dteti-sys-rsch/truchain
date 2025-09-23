const router = require('express').Router()

const { createVerifiedBank } = require('../controllers/bank')

router.post('/', createVerifiedBank)

module.exports = router
