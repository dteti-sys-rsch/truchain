const jwt = require('jsonwebtoken')
const Account = require('../models/account')
const bcrypt = require('bcrypt')

exports.register = async (req, res) => {
  const { username, password } = req.body

  Account.findOne({ username })
    .then((existingUser) => {
      if (existingUser) {
        return res.status(400).json({ message: 'Username already exists' })
      }

      bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
          return res.status(500).json({ error: err })
        }

        const newAccount = new Account({
          username,
          password: hash
        })

        newAccount
          .save()
          .then(() => {
            res.status(201).json({ message: 'Account created successfully' })
          })
          .catch((error) => {
            res.status(500).json({ error })
          })
      })
    })
    .catch((error) => {
      res.status(500).json({ error })
    })
}

exports.login = async (req, res) => {
  const { username, password } = req.body

  Account.findOne({ username })
    .then((user) => {
      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' })
      }

      bcrypt.compare(password, user.password, (err, result) => {
        if (err) {
          return res.status(401).json({ message: 'Invalid credentials' })
        }

        if (result) {
          const token = jwt.sign(
            { username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
          )
          return res.status(200).json({ token })
        } else {
          return res.status(401).json({ message: 'Invalid credentials' })
        }
      })
    })
    .catch((error) => {
      res.status(500).json({ error })
    })
}
