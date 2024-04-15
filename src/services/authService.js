import db from "../models/index";
import bcrypt from "bcryptjs";
require("dotenv").config();
import { Op } from "sequelize";
import { createJWT, createRefreshToken } from "./jwtService";
const uuid = require('uuid');

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
    serviceName: user.Service.serviceName,
    serviceUrl: user.Service.serviceUrl
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

const checkUserPassword = (password, passwordHash) => {
  return bcrypt.compareSync(password, passwordHash);
}

const checkService = async (serviceName, serviceUrl) => {
  const service = await db.Service.findOne({
    where: {
      [Op.or]: [
        { serviceName },
        { serviceUrl }
      ]

    }
  })
  return service;
}

const registerUser = async (data) => {
  try {
    const isExistedEmail = await checkEmailExist(data.email);
    if (isExistedEmail) {
      return {
        message: "Email already registered.",
        statusCode: 409,
      }
    }
    const isExistedUsername = await checkUsernameExist(data.username);
    if (isExistedUsername) {
      return {
        message: "Username already registered.",
        statusCode: 409,
      }
    }
    const passwordHash = hashUserPassword(data.password);
    let newService;
    const service = await checkService(data.serviceName, data.serviceUrl);
    if (!service) {
      newService = await db.Service.create(
        {
          id: uuid.v4(),
          serviceName: data.serviceName,
          serviceUrl: data.serviceUrl,
          isActive: true,
        }
      )
    }
    else {
      newService = service;
    }
    const newUser = await db.User.create(
      {
        email: data.email,
        username: data.username,
        password: passwordHash,
        role: "member",
        serviceId: newService.id
      }
    );
    console.log(newUser.toJSON());
    return {
      message: "Registed successfully.",
      statusCode: 201
    }
  } catch (error) {
    console.log(error);
    return {
      message: "Error creating",
      statusCode: 500,
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
      },
      include: db.Service
    });
    if (user) {
      const isCorrectPassword = checkUserPassword(data.password, user.password);
      if (isCorrectPassword) {
        const payload = getListClaim(user);
        const token = createJWT(payload);
        const refreshToken = createRefreshToken();

        await db.userToken.create({
          accessToken: token,
          refreshToken,
          expires: new Date(new Date().setMinutes(new Date().getMinutes() + 10)),
          userId: user.id
        })
        return {
          user: {
            username: user.username,
            email: user.email,
            role: user.role,
            accessToken: token,
            refreshToken,
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

const refreshToken = async (refreshToken) => {
  if (!refreshToken) {
    return {
      message: "Refresh token failed",
      statusCode: 403
    };
  }

  const currRfToken = await db.userToken.findOne({
    where: {
      refreshToken,
    }
  })

  if (!currRfToken || currRfToken.expires.getTime() <= Date.now()) {
    if (currRfToken) {
      await db.userToken.destroy({
        where: {
          refreshToken: currRfToken,
        },
      });
    }
    return {
      message: "Refresh token failed",
      statusCode: 403
    };
  }

  const user = await db.User.findOne({
    where: {
      id: currRfToken.userId,
    },
    include: db.Service
  })
  const payload = getListClaim(user);
  const newAccessToken = createJWT(payload);
  const newRefreshToken = createRefreshToken();
  await db.userToken.update(
    {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expires: new Date(new Date().setMinutes(new Date().getMinutes() + 10)),
      updatedAt: new Date(),
    },
    {
      where: {
        userId: user.id,
      },
    },
  );
  return {
    message: "Refresh token successfully.",
    statusCode: 200,
    accessToken: newAccessToken,
    refreshToken: newRefreshToken
  }
}

export { registerUser, loginUser, refreshToken }