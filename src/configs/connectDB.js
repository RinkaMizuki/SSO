import { Sequelize } from "sequelize";
require("dotenv").config();

// Option 3: Passing parameters separately (other dialects)
const sequelize = new Sequelize(process.env.DATABASE, process.env.ROOT, process.env.PASSWORD, {
  host: process.env.HOST,
  dialect: process.env.DIALECT,
});

const connection = async () => {
  try {
    await sequelize.authenticate();
    console.log('Connection has been established successfully.');
  } catch (error) {
    console.error('Unable to connect to the database:', error);
  }
}

export default connection;

