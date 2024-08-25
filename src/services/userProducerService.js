class StartUserProducer {
  static channel;
  static routingKey = "UserRegistered";
  static exchangeName = "outboxMessageExchange";

  constructor(connection) {
    return this.init(connection);
  }

  async init(connection) {
    try {
      console.log(">>> Producer started and publishing for messages...");
      StartUserProducer.channel = await connection.createChannel();
      return await StartUserProducer.channel.assertExchange(
        StartUserProducer.exchangeName,
        "direct",
        {
          durable: true,
        }
      );
    } catch (error) {
      console.error("Error starting producer:", error);
    }
  }

  static publishUserRegister(message) {
    if (!StartUserProducer.channel) {
      console.error("Channel is not initialized. Cannot publish message.");
      return;
    }

    const messageBuffer = Buffer.from(
      typeof message === "string" ? message : JSON.stringify(message)
    );

    StartUserProducer.channel.publish(
      StartUserProducer.exchangeName,
      StartUserProducer.routingKey,
      messageBuffer,
      {
        persistent: true,
      }
    );
    console.log("Message published:", message);
  }
}

export default StartUserProducer;
