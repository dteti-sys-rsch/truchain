const router = require('express').Router()

const { createTransaction, queryTransactions } = require('../controllers/transaction')

router.post('/', createTransaction)
router.get('/', queryTransactions)

module.exports = router
