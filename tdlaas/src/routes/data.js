const router = require('express').Router()

const { verifyVC, storeData, queryData, verifyAndStoreData } = require('../controllers/data')
const { endToEnd, endToEndProd, l2extension }  = require('../controllers/full')

router.post('/verify', verifyVC)
router.post('/store', storeData)
router.get('/query', queryData)
router.post('/verifyAndStore', verifyAndStoreData)
router.post('/endToEnd', endToEnd)
router.post('/endToEndProd', endToEndProd)

// TEST
router.post('/l2extension', l2extension)

module.exports = router
