const redis = require('redis')

let redisClient

if (process.env.REDIS_SETTING === 'local') {
  console.log('Using local Redis')
  redisClient = redis.createClient()
} else {
  console.log('Using Upstash Redis')
  redisClient = redis.createClient({
    url: process.env.UPSTASH_REDIS_URL
  })
}

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
