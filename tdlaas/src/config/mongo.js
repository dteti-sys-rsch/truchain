const mongoose = require('mongoose')
const dotenv = require('dotenv')
dotenv.config({ path: '../../config.env'})

const connectDB = async () => {
  try {
    await mongoose
      .set('strictQuery', false)
      .connect('mongodb://127.0.0.1:27017/truchain')
      .then(() => {
        console.log('MongoDB Connected!')
      })
      .catch((err) => console.log(err))
  } catch (err) {
    console.error(err)
    process.exit(1)
  }
}

module.exports = connectDB
