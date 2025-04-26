const router = require('express').Router()

const { verifyVC, storeData, queryData } = require('../controllers/data')

router.post('/verify', verifyVC)
router.post('/store', storeData)
router.get('/query', queryData)

module.exports = router
