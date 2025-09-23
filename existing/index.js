const express = require('express')
const morgan = require('morgan')
const cors = require('cors')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const app = express()

// DOTENV
const dotenv = require('dotenv')
dotenv.config()

// MONGODB
const connectDB = require('./src/config/mongo')
connectDB()

// MIDDLEWARE
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(cookieParser())
app.use(morgan('dev'))

// CORS
app.use(cors())

// ROUTES
app.get('/', (req, res) => {
  res.send('Hello from Open Banking Mock System!')
})
app.use('/api/auth', require('./src/routes/auth'))
app.use('/api/transaction', require('./src/routes/transaction'))
app.use('/api/bank', require('./src/routes/bank'))

app.use((req, res, next) => {
  const error = new Error('Not found!')
  error.status = 404
  next(error)
})
app.use((error, req, res, next) => {
  res.status(error.status || 500)
  res.json({
    error: {
      message: error.message
    }
  })
})

// SERVER
const port = process.env.PORT || 5003
app.listen(port, () => {
  console.log('Server is running!')
})

module.exports = app
