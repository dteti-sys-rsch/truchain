const express = require('express')
const morgan = require('morgan')
const cors = require('cors')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const app = express()

// DOTENV
const dotenv = require('dotenv')
dotenv.config()

// MIDDLEWARE
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(cookieParser())
app.use(morgan('dev'))

// CORS
app.use(cors())

// ROUTES
app.get('/', (req, res) => {
  res.send('Hello from TDLaaS Source Node Module!')
})

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
const port = process.env.PORT || 5002
app.listen(port, () => {
  console.log('Server is running!')
})

module.exports = app
