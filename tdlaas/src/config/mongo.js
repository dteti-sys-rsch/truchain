const mongoose = require('mongoose')

const connectDB = async () => {
  try {
    await mongoose
      .set('strictQuery', false)
      .connect(process.env.MONGODB_URI)
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