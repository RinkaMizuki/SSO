import { checkService, hashUserPassword } from "./authService";
import db, { sequelize } from "../models/index";
import { v4 as uuidv4 } from "uuid";

class StartUserConsumer {
  constructor(connection) {
    this.init(connection);
  }

  async createUserInNodeJsService({ user, password, serviceName, serviceUrl }) {
    const t = await sequelize.transaction();
    try {
      let newService;
      const service = await checkService(serviceName, serviceUrl);
      if (!service) {
        newService = await db.Service.create(
          {
            id: uuidv4(),
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

  async init(connection) {
    try {
      const channel = await connection.createChannel();
      const queue = "addUserOutboxQueue";

      await channel.assertExchange("outboxMessageExchange", "direct", {
        durable: true,
      });

      await channel.assertQueue(queue, { durable: true });
      await channel.bindQueue(queue, "outboxMessageExchange", "UserCreated");

      channel.consume(queue, async (msg) => {
        if (msg !== null) {
          const user = JSON.parse(msg.content.toString());
          await this.createUserInNodeJsService(user);
          channel.ack(msg);
        }
      });

      console.log(">>> Consumer started and listening for messages...");
    } catch (error) {
      console.error("Error starting consumer:", err);
    }
  }
}

export default StartUserConsumer;
