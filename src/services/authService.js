import db from "../models/index";
import bcrypt from "bcryptjs";
require("dotenv").config();
import { Op } from "sequelize";
import jwt from "jsonwebtoken";

const salt = bcrypt.genSaltSync(10);

const checkEmailExist = async (email) => {
  const user = await db.User.findOne({
    where: { email }
  })
  if (user) {
    return true;
  }
  return false;
}

const getListClaim = (user) => {
  return {
    email: user.email,
    username: user.username,
    role: user.role,
  }
}

const checkUsernameExist = async (username) => {
  const user = await db.User.findOne({
    where: { username }
  })
  if (user) {
    return true;
  }
  return false;
}

const hashUserPassword = (password) => {
  const hashPassword = bcrypt.hashSync(password, salt);
  return hashPassword;
}

const createJWT = (payload) => {
  return jwt.sign(payload, process.env.SECRET, {
    algorithm: 'HS256',
    expiresIn: process.env.EXPIRES,
    issuer: process.env.ISSUER,
    audience: process.env.AUDIENCE,
  })
}

const checkUserPassword = (password, passwordHash) => {
  return bcrypt.compareSync(password, passwordHash);
}

const registerUser = async (data) => {
  try {
    if (!checkEmailExist(data.email)) {
      return {
        message: "Email already registered.",
        statusCode: 409,
      }
    }
    if (!checkUsernameExist(data.username)) {
      return {
        message: "Username already registered.",
        statusCode: 409,
      }
    }
    const passwordHash = hashUserPassword(data.password);
    const newUser = await db.User.create({
      email: data.email,
      username: data.username,
      password: passwordHash,
      role: "member"
    });
    console.log(newUser.toJSON());
    return {
      message: "Register successfully",
      statusCode: 200
    }
  } catch (error) {
    return {
      message: "Error creating",
      statusCode: error.statusCode,
    }
  }
}

const loginUser = async (data) => {
  try {
    const user = await db.User.findOne({
      where: {
        [Op.or]: [
          { email: data.valueLogin },
          { username: data.valueLogin }
        ]
      }
    });
    if (user) {
      const isCorrectPassword = checkUserPassword(data.password, user.password);
      if (isCorrectPassword) {
        const payload = getListClaim(user);
        const token = createJWT(payload);
        return {
          user: {
            username: user.username,
            email: user.email,
            role: user.role,
            accessToken: token
          },
          message: "Login successfully.",
          statusCode: 200
        }
      }
      else {
        return {
          message: 'Password incorrect.',
          statusCode: 400
        }
      }
    } else {
      return {
        message: 'Email/Username incorrect.',
        statusCode: 404
      }
    }
  } catch (error) {
    console.log(error);
    return {
      message: error.message,
      statusCode: error.statusCode,
    }
  }
}

export { registerUser, loginUser }