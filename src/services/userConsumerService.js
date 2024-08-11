import amqp from "amqplib";
import { checkService, hashUserPassword } from "./authService";
import db, { sequelize } from "../models/index";

async function createUserInNodeJsService({
  user,
  password,
  serviceName,
  serviceUrl,
}) {
  const t = await sequelize.transaction();
  try {
    let newService;
    const service = await checkService(serviceName, serviceUrl);
    if (!service) {
      newService = await db.Service.create(
        {
          id: uuid.v4(),
          serviceName: serviceName,
          serviceUrl: serviceUrl,
          isActive: true,
        },
        { transaction: t }
      );
    } else {
      newService = service;
    }
    const passwordHash = hashUserPassword(password);
    const newUser = {
      id: user.UserId,
      email: user.Email,
      username: user.UserName,
      password: passwordHash,
      role: user.Role,
      emailConfirm: user.EmailConfirm,
      phone: user.Phone,
      createdAt: user.CreatedAt,
      updatedAt: user.ModifiedAt,
      serviceId: newService.id,
    };
    await db.User.create(newUser, {
      transaction: t,
    });
    await t.commit();
  } catch (error) {
    await t.rollback();
    console.error(error);
  }
}

async function startUserConsumer() {
  const rabbitmqUri = `amqp://${process.env.RB_USERNAME}:${process.env.RB_PASSWORD}@${process.env.RB_HOSTNAME}`;
  const connection = await amqp.connect(rabbitmqUri);
  const channel = await connection.createChannel();
  const queue = "addUserOutboxQueue";

  await channel.assertExchange("outboxMessageExchange", "direct", {
    durable: true,
  });

  // Khai báo hàng đợi
  await channel.assertQueue(queue, { durable: true });

  // Ràng buộc hàng đợi với exchange bằng routing key
  await channel.bindQueue(queue, "outboxMessageExchange", "UserCreated");

  channel.consume(queue, async (msg) => {
    if (msg !== null) {
      const user = JSON.parse(msg.content.toString());
      await createUserInNodeJsService(user);
      channel.ack(msg);
    }
  });
}

export default startUserConsumer;
