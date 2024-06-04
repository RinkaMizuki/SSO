import { createClient } from 'redis';

const client = createClient({
  socket: {
    reconnectStrategy: function (retrires) {
      if (retrires > 20) {
        console.log("Too many attempts to reconnect. Redis connection was terminated");
        return new Error("Too many retries.");
      }
      else {
        return retrires * 500
      }
    },
    connectTimeout: 10000
  }
});

client.on('error', err => console.log('Redis Client Error', err));

export default async function connectionRedis() {
  return client.connect().then(async () => {
    console.log(">>> Redis connection established");
  }).catch(error => console.log(error));
}

export { client as redisClient }