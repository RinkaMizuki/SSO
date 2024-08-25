import amqp from "amqplib";

export default async function connectRabbitMQ() {
  try {
    const rabbitmqUri = `amqp://${process.env.RB_USERNAME}:${process.env.RB_PASSWORD}@${process.env.RB_HOSTNAME}`;
    const connection = await amqp.connect(rabbitmqUri);
    return connection;
  } catch (error) {
    console.log("Connecting to RabbitMQ failed: ", error);
  }
}
