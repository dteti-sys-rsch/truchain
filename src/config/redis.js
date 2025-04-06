const redis = require('redis')

const redisClient = redis.createClient({
  url: process.env.UPSTASH_REDIS_URL
})

;(async () => {
  redisClient.on('error', (err) => {
    console.log('Redis Client Error', err)
  })

  redisClient.on('ready', () => console.log('Redis is Ready! Checking connection...'))

  try {
    await redisClient.connect()
    const pong = await redisClient.ping()
    console.log('Redis PING Response:', pong)
  } catch (err) {
    console.error('Failed to connect to Redis:', err)
  }
})()

module.exports = redisClient
