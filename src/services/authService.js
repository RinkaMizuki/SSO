import db, { sequelize } from "../models/index";
import bcrypt from "bcryptjs";
require("dotenv").config();
import { Op } from "sequelize";
import { createFacebookJWT, createJWT, createRefreshToken } from "./jwtService";
const uuid = require('uuid');
const jwt = require('jsonwebtoken');
const randomstring = require("randomstring");
import axios from "axios";
import { createEmailConfirmToken, createResetPasswordToken, sendMailAsync } from "./mailService";
import { timeExpires } from "./timeExpires";
import { redisClient } from "../configs/connectRedis";
const nodeCache = require("node-cache");
const otpCache = new nodeCache();

const salt = bcrypt.genSaltSync(10);

const getUserInfo = async (userId, userService) => {
  try {
    const httpRequest = axios.create({
      baseURL: userService === "Ecommerce" ? process.env.ECOMMERCE_BASE_URL : "",
    })
    const response = await httpRequest.get('api/v1/Admin/users/' + userId);
    return response.data;
  } catch (err) {
    console.log(err);
    throw err;
  }
}

const postUserInfo = async (data, userService) => {
  try {
    const httpRequest = axios.create({
      baseURL: userService === "Ecommerce" ? process.env.ECOMMERCE_BASE_URL : "",//cần truyền serviceName để call api của service đó
    })
    const response = await httpRequest.post('api/v1/Admin/users/post', data);
    return response.data;
  } catch (err) {
    console.log(err);
    throw err;
  }
}

const updateUserConfirm = async (userId, userService) => {
  try {
    const httpRequest = axios.create({
      baseURL: userService === "Ecommerce" ? process.env.ECOMMERCE_BASE_URL : "",//cần truyền serviceName để call api của service đó
    })
    const response = await httpRequest.get(`api/v1/Admin/users/confirm-email/${userId}`);
    return response.data;
  } catch (err) {
    console.log(err);
    throw err;
  }
}

const getUserFacebookInfo = async (token) => {
  try {
    const res = await axios.get(`https://graph.facebook.com/v19.0/me?fields=id,name,email,picture&access_token=${token}`);
    return res.data;
  }
  catch (err) {
    return {
      message: err.message,
      statusCode: 400,
    }
  }
}

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
    userId: user.id,
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

const setRedisToken = async (token) => {
  const tokenExpires = jwt.decode(token);
  if (tokenExpires.exp > Date.now() / 1000) {
    await redisClient.set(token, `bl_${tokenExpires.email}`, {
      EXAT: tokenExpires.exp
    })
  }
}

const validateEmailConfirmToken = (token) => {
  const secret = process.env.SECRET;
  return jwt.verify(token, secret, {
    issuer: process.env.ISSUER,
    audience: process.env.AUDIENCE,
  }, function (err, decoded) {
    if (err) {
      console.log(err);
      return false;
    }
    else {
      if (decoded.type != "confirm") {
        console.log("decoded.type: ", decoded.type);
        return false;
      }
      return true;
    }
  });
}

const validateResetPasswordToken = (token) => {
  const secret = process.env.SECRET;
  return jwt.verify(token, secret, {
    issuer: process.env.ISSUER,
    audience: process.env.AUDIENCE,
  }, function (err, decoded) {
    if (err) {
      console.log(err);
      return false;
    }
    else {
      if (decoded.type != "reset") {
        return false;
      }
      return true;
    }
  });
}

const validateOtp = (data) => {
  if (!data?.phone || !data?.otp) {
    return {
      statusCode: 401,
      message: "Invalid otp/phone."
    }
  }
  const value = otpCache.get(`otp_${data?.phone}`);
  if (!value) {
    return {
      statusCode: 404,
      message: "Your otp expired. Please try again.",
    }
  }
  if (value.toString() != data?.otp.toString()) {
    return {
      statusCode: 401,
      message: "Invalid/Incorrect otp. Please try again.",
    }
  }
  return {
    statusCode: 200,
    message: "Valid otp."
  }
}

const registerUser = async (data) => {
  const t = await sequelize.transaction();
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
        }, { transaction: t }
      )
    }
    else {
      newService = service;
    }
    const newUser = {
      id: uuid.v4(),
      email: data.email,
      username: data.username,
      password: passwordHash,
      role: "member",
      serviceId: newService.id
    };
    await db.User.create(newUser, {
      transaction: t
    });
    await postUserInfo({
      UserId: newUser.id,
      UserName: data.username,
      Email: data.email,
      BirthDate: new Date(),
      CreatedAt: new Date(),
      ModifiedAt: new Date(),
      EmailConfirm: false,
      Url: "",
      Avatar: ""
    }, data.serviceName)
    const token = createEmailConfirmToken(newUser, "1h");
    const message = `${data.serviceUrl}confirm-email?email=${newUser.email}&token=${token}&serviceName=${data.serviceName}`;
    await sendMailAsync(newUser.email, "Please confirm your email.", `Click here to confirm your email. <a href=\"${message}\">Click here!</a>`)
    await t.commit();
    return {
      message: "Registed successfully.",
      statusCode: 201
    }
  } catch (error) {
    await t.rollback();
    console.log(error);
    return {
      message: "Error creating",
      statusCode: 500,
    }
  }
}

const postLogout = async (rt, at, userId) => {
  try {
    if (!rt && !userId && !at) {
      return {
        statusCode: 200,
        message: "Logged out successfully."
      }
    }
    if (at) {
      await setRedisToken(at)
    }
    await db.UserToken.destroy({
      where: {
        [Op.or]: [
          { refreshToken: rt ?? "nohope" },
          { accessToken: at ?? "nohope" },
          { userId: userId ?? -1 }
        ]
      },
      force: true,
    });
    return {
      statusCode: 200,
      message: "Logged out successfully."
    }
  } catch (err) {
    console.log(err);
    return {
      statusCode: 500,
      message: err.message
    }
  }
}

const postLogin = async (data) => {
  const t = await sequelize.transaction();
  try {
    const user = await db.User.findOne({
      where: {
        [Op.and]: [
          {
            [Op.or]: [
              { email: data.valueLogin },
              { username: data.valueLogin }
            ]
          },
          { emailConfirm: true }
        ],
      },
      include: [db.Service, db.UserLogin]
    });
    if (user) {
      //check if user login with correct infomation
      const isCorrectPassword = checkUserPassword(data.password, user.password);
      if (isCorrectPassword) {
        const userInfoExtend = await getUserInfo(user.id, user.Service.serviceName);
        if (userInfoExtend.isActive) {
          await t.commit();
          return {
            isBan: true,
            statusCode: 403,
            message: "Your account has been banned. Please contact admin@gmail.com for more details."
          }
        }
        user.UserLogins.forEach(ul => {
          userInfoExtend.userLogins.push({
            loginProvider: ul.loginProvider,
            providerKey: ul.providerKey,
            providerDisplayName: ul.providerDisplayName,
            userId: ul.userId,
            accountAvatar: ul.accountAvatar,
            accountName: ul.accountName,
            isUnlink: ul.isUnlink,
          })
        })
        userInfoExtend.f2a = user.f2a;
        const payload = getListClaim(user);
        const token = createJWT(payload);
        const refreshToken = createRefreshToken();

        //check if user is already logged in other session so we remove it token 
        const isLoggedIn = await db.UserToken.findOne({
          where: {
            userId: user.id
          }
        })
        if (isLoggedIn) {
          await db.UserToken.update(
            {
              accessToken: token,
              refreshToken,
              expires: !data.remember ? timeExpires.notRemember : timeExpires.remember,
              updatedAt: new Date(),
            },
            {
              where: {
                userId: isLoggedIn.userId,
              },
              transaction: t
            },
          )
          await setRedisToken(isLoggedIn.accessToken)
        }
        else {
          await db.UserToken.create({
            accessToken: token,
            refreshToken,
            expires: !data.remember ? timeExpires.notRemember : timeExpires.remember,
            userId: user.id
          }, { transaction: t })
        }

        await t.commit();
        return {
          user: userInfoExtend,
          accessToken: token,
          refreshToken,
          message: "Login successfully.",
          statusCode: 200
        }
      }
      else {
        await t.commit();
        return {
          message: 'Password incorrect.',
          statusCode: 400
        }
      }
    } else {
      await t.commit();
      return {
        message: 'Email/Username incorrect or unconfimred.',
        statusCode: 404
      }
    }
  } catch (error) {
    console.log(error);
    await t.rollback();
    return {
      message: error.message,
      statusCode: error.statusCode,
    }
  }
}

const forgotPassword = async (data) => {
  try {
    const user = await db.User.findOne({
      where: {
        email: data?.email,
      },
      include: [db.Service]
    })
    if (!user) {
      return {
        statusCode: 404,
        message: "Email not found."
      }
    }
    const payload = getListClaim(user);
    const token = createResetPasswordToken(payload, 5 * 60);
    const message = `${data.returnUrl}?token=${token}`;
    await sendMailAsync(user.email, "Reset your password", `Click here to reset your password. <a href="${message}">Click here!</a>`);

    return {
      statusCode: 200,
      message: "Please check your email to reset password"
    }

  } catch (error) {
    return {
      statusCode: 500,
      message: error.message
    }
  }
}

const resetPassword = async (data) => {
  try {
    if (!data.token) {
      return {
        statusCode: "401",
        message: "Invalid token."
      }
    }
    const result = validateResetPasswordToken(data.token)
    if (result) {
      const claims = jwt.decode(data.token)
      const newPassword = hashUserPassword(data.password, salt);
      await db.User.update(
        { password: newPassword },
        {
          where: {
            email: claims.email
          }
        }
      )
      return {
        message: "Reset password successfully.",
        statusCode: 200,
      }
    }
    return {
      statusCode: 400,
      message: "Reset password failed.",
    };
  } catch (error) {
    return {
      message: error.message,
      statusCode: 500
    }
  }
}

const changePassword = async (data) => {
  try {
    const user = await db.User.findOne({
      where: {
        id: data.userId
      }
    })
    if (!user) {
      return {
        message: 'User not found',
        statusCode: 404
      }
    }
    const isCorrectPassword = checkUserPassword(data.currentPassword, user.password);
    if (isCorrectPassword) {
      await db.User.update(
        { password: hashUserPassword(data.newPassword, salt) },
        {
          where: {
            id: user.id
          }
        }
      )
      return {
        message: 'Update password successfully.',
        statusCode: 200
      }
    }
    else {
      return {
        message: 'Current password incorrect.',
        statusCode: 409
      }
    }
  } catch (error) {
    return {
      message: error.message,
      statusCode: 500
    }
  }
}

const confirmEmail = async (data) => {
  const t = await sequelize.transaction();
  try {
    const userConfirm = await db.User.findOne({
      where: {
        email: data.email,
      },
    })
    if (!userConfirm) {
      return {
        statusCode: 404,
        message: "User not found."
      }
    }
    const isValid = validateEmailConfirmToken(data.token);
    if (!isValid) {
      return {
        message: "Confirm email failure.",
        statusCode: 400,
      }
    }
    if (userConfirm.emailConfirm) {
      return {
        message: "Your email have been confirmed.",
        statusCode: 409,
      }
    }

    await db.User.update(
      { emailConfirm: true },
      {
        where: { email: data.email },
        transaction: t
      },
    );
    await updateUserConfirm(userConfirm.id, data.serviceName);
    await t.commit();
    return {
      statusCode: 200,
      message: "Confirm email successfully."
    }

  } catch (err) {
    await t.rollback();
    console.log(err);
    return {
      statusCode: 500,
      message: err.message
    }
  }
}

const enableF2A = async (params) => {
  const otpCode = randomstring.generate({
    length: 4,
    charset: 'numeric'
  });
  console.log("otpCode:::", otpCode);
  const data = JSON.stringify({
    "from": {
      "type": "external",
      "number": process.env.STRINGEE_PHONE,
      "alias": "STRINGEE_NUMBER"
    },
    "to": [
      {
        "type": "external",
        "number": params?.phone.startsWith('0') ? params?.phone.replace('0', '84') : params?.phone,
        "alias": "TO_NUMBER"
      }
    ],
    "answer_url": "https://example.com/answerurl",
    "actions": [
      {
        "action": "talk",
        "text": `Vui lòng không để lộ mã xác thực. Mã xác thực của bạn là ${otpCode}`
      }
    ]
  });
  const config = {
    method: 'post',
    maxBodyLength: Infinity,
    url: 'https://api.stringee.com/v1/call2/callout',
    headers: {
      'X-STRINGEE-AUTH': process.env.STRINGEE_TOKEN, // save into cache with expired cache = expired token
      'Content-Type': 'application/json',
      'Cookie': 'SRVNAME=SD'
    },
    data: data
  };

  return axios.request(config)
    .then(async (response) => {
      const success = otpCache.set(`otp_${params?.phone}`, otpCode.toString(), 60);
      if (success) {
        return {
          message: response?.data?.message,
          statusCode: 200
        }
      }
      return {
        message: "Something went wrong.",
        statusCode: 500
      }
    })
    .catch((error) => {
      console.log(error);
      return {
        message: error.message,
        statusCode: 400
      }
    });
}

const verifyOtp = async (data, verifyType) => {
  const t = await sequelize.transaction();
  try {
    const otpValidateResult = validateOtp(data);
    if (otpValidateResult.statusCode === 404 || otpValidateResult.statusCode === 401) {
      return otpValidateResult;
    }

    if (verifyType === 'verify-f2a') {
      const user = await db.User.findOne({
        where: {
          id: data?.userId
        },
        include: [db.Service, db.UserLogin]
      })
      if (!user) {
        return {
          statusCode: 404,
          message: "User not found."
        }
      }
      await db.User.update(
        {
          f2a: data?.isF2A,
          phone: data?.phone
        },
        {
          where: {
            id: data?.userId
          },
          transaction: t
        })
      const userInfoExtend = await getUserInfo(data?.userId, user?.Service.serviceName);
      user.UserLogins.forEach(ul => {
        userInfoExtend.userLogins.push({
          loginProvider: ul.loginProvider,
          providerKey: ul.providerKey,
          providerDisplayName: ul.providerDisplayName,
          userId: ul.userId,
          accountAvatar: ul.accountAvatar,
          accountName: ul.accountName,
          isUnlink: ul.isUnlink,
        })
      })
      userInfoExtend.f2a = data?.isF2A;
      await t.commit();
      return {
        statusCode: 200,
        message: data?.isF2A ? "Enabled F2A successfully." : "Disabled F2A successfully.",
        user: userInfoExtend,
      }
    } else if (verifyType === 'verify-login') {
      const user = await db.User.findOne({
        where: {
          phone: data?.phone
        },
        include: [db.Service, db.UserLogin]
      })
      if (!user) {
        return {
          statusCode: 404,
          message: "User not found."
        }
      }
      const userInfoExtend = await getUserInfo(user?.id, user?.Service.serviceName);
      user.UserLogins.forEach(ul => {
        userInfoExtend.userLogins.push({
          loginProvider: ul.loginProvider,
          providerKey: ul.providerKey,
          providerDisplayName: ul.providerDisplayName,
          userId: ul.userId,
          accountAvatar: ul.accountAvatar,
          accountName: ul.accountName,
          isUnlink: ul.isUnlink,
        })
      })
      userInfoExtend.f2a = user?.f2a;
      await t.commit();

      return {
        statusCode: 200,
        message: "Login successfully.",
        user: userInfoExtend
      }
    }

  } catch (error) {
    await t.rollback();
    console.log(error);
    return {
      statusCode: 400,
      message: error.message
    }
  }
}

const getUserGoogleInfo = async (token_type, access_token) => {
  const res = await axios.get(process.env.GOOGLE_USERINFO_SCOPE_URI, {
    headers: {
      "Authorization": `${token_type} ${access_token}`,
    },
  })
  return res;
}

const getTokenGoogle = async (code) => {
  const { data: { access_token, expires_in, id_token, refresh_token, scope, token_type } } = await axios.post(`${process.env.GOOGLE_TOKEN_URI}/token`, null, {
    params: {
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      code,
      grant_type: "authorization_code",
      redirect_uri: process.env.GOOGLE_REDIRECT_URI
    }
  })
  const res = await getUserGoogleInfo(token_type, access_token);

  const data = {
    providerId: res.data.id,
    email: res.data.email,
    providerName: "Google",
    providerDisplayName: "Google",
    picture: res.data.picture,
    accessToken: id_token,
    refreshToken: refresh_token
  }
  return data;
}

const loginGoogle = async (params) => {
  const t = await sequelize.transaction();
  try {
    const data = await getTokenGoogle(params.code);
    const userLink = await db.User.findOne({
      where: {
        email: data.email
      }
    });
    const userLogins = await db.UserLogin.findOne({
      where: {
        providerKey: data.providerId
      }
    });
    if (userLogins != null) {
      const user = await db.User.findOne({
        where: {
          id: userLogins.userId
        },
        include: [db.UserLogin]
      })

      await db.UserToken.create({
        accessToken: data.accessToken,
        refreshToken: data.refreshToken,
        expires: timeExpires.notRemember,
        userId: user.id
      }, { transaction: t })

      const userInfoExtend = await getUserInfo(user.id, params.serviceName);
      user.UserLogins.forEach(ul => {
        userInfoExtend.userLogins.push({
          loginProvider: ul.loginProvider,
          providerKey: ul.providerKey,
          providerDisplayName: ul.providerDisplayName,
          userId: ul.userId,
          accountAvatar: ul.accountAvatar,
          accountName: ul.accountName,
          isUnlink: ul.isUnlink,
        })
      })
      await t.commit();
      return {
        statusCode: 200,
        message: "Login successfully.",
        user: userInfoExtend,
        accessToken: data.accessToken,
        refreshToken: data.refreshToken
      }
    }
    if (userLink && !userLogins) {
      const newProvider = {
        userId: userLink.id,
        loginProvider: data.providerName,
        providerKey: data.providerId,
        providerDisplayName: data.providerDisplayName,
        accountAvatar: data.picture,
        accountName: data.email,
        isUnlink: !!userLink?.password || !!userLink.UserLogins?.length,
      }
      await db.UserLogin.create(newProvider, { transaction: t });
      const user = await db.User.findOne({
        where: {
          id: newProvider.userId
        },
        include: [db.UserLogin]
      })
      await db.UserToken.create({
        accessToken: data.accessToken,
        refreshToken: data.refreshToken,
        expires: timeExpires.notRemember,
        userId: user.id
      }, { transaction: t })

      const userInfoExtend = await getUserInfo(user.id, params.serviceName);
      user.UserLogins.forEach(ul => {
        userInfoExtend.userLogins.push({
          loginProvider: ul.loginProvider,
          providerKey: ul.providerKey,
          providerDisplayName: ul.providerDisplayName,
          userId: ul.userId,
          accountAvatar: ul.accountAvatar,
          accountName: ul.accountName,
          isUnlink: ul.isUnlink,
        })
      })
      await t.commit();
      return {
        statusCode: 200,
        message: "Login successfully.",
        user: userInfoExtend,
        accessToken: data.accessToken,
        refreshToken: data.refreshToken,
      }
    } else {
      const userId = uuid.v4();
      const newUserWithProvider = {
        UserId: userId,
        UserName: data.email,
        Email: data.email,
        BirthDate: new Date(),
        CreatedAt: new Date(),
        ModifiedAt: new Date(),
        EmailConfirm: true,
        Url: data.picture,
        Avatar: "Provider Avatar"
      }
      const response = await postUserInfo(newUserWithProvider, params.serviceName)
      const newProvider = {
        userId: userId,
        loginProvider: data.providerName,
        providerKey: data.providerId,
        providerDisplayName: data.providerDisplayName,
        accountAvatar: data.picture,
        accountName: data.email,
        isUnlink: false,
      }
      const service = await db.Service.findOne({
        where: {
          serviceName: params.serviceName,
        }
      })
      await db.User.create({
        id: userId,
        email: newUserWithProvider.Email,
        username: newUserWithProvider.UserName,
        role: "member",
        serviceId: service.id
      }, { transaction: t });
      await db.UserLogin.create(newProvider, { transaction: t });
      const providers = await db.UserLogin.findAll({
        where: {
          userId: userId
        }
      })

      await db.UserToken.create({
        accessToken: data.accessToken,
        refreshToken: data.refreshToken,
        expires: timeExpires.notRemember,
        userId: userId
      }, { transaction: t })

      providers.forEach(ul => {
        response.userLogins.push({
          loginProvider: ul.loginProvider,
          providerKey: ul.providerKey,
          providerDisplayName: ul.providerDisplayName,
          userId: ul.userId,
          accountAvatar: ul.accountAvatar,
          accountName: ul.accountName,
          isUnlink: ul.isUnlink,
        })
      })
      await t.commit();
      return {
        statusCode: 200,
        message: "Login successfully.",
        user: response,
        accessToken: data.accessToken,
        refreshToken: data.refreshToken
      }
    }
  } catch (error) {
    console.log(error);
    await t.rollback();
    return {
      statusCode: 500,
      message: error.message
    }
  }
}

const unlinkGoogle = async (data) => {
  try {
    const rcChange = await db.UserLogin.destroy({
      where: {
        [Op.and]: [
          { userId: data.userId },
          { providerKey: data.providerId }
        ]
      },
      force: true,
    });
    if (!rcChange) {
      return {
        statusCode: 404,
        message: "UserID/ProviderID incorrect."
      }
    }
    const userLinked = await db.User.findOne({
      where: {
        id: data.userId,
      },
      include: [db.UserLogin, db.Service]
    })
    const userInfoExtend = await getUserInfo(userLinked.id, userLinked.Service.serviceName);
    userLinked.UserLogins.forEach(ul => {
      userInfoExtend.userLogins.push({
        loginProvider: ul.loginProvider,
        providerKey: ul.providerKey,
        providerDisplayName: ul.providerDisplayName,
        userId: ul.userId,
        accountAvatar: ul.accountAvatar,
        accountName: ul.accountName,
        isUnlink: ul.isUnlink,
      })
    })
    return {
      statusCode: 200,
      message: "Unlinked provider successfully.",
      user: userInfoExtend,
    }
  } catch (error) {
    console.log(error);
    return {
      statusCode: 500,
      message: error.message
    }
  }
}

const loginFacebook = async (data) => {
  const t = await sequelize.transaction();
  try {
    const userProfile = await getUserFacebookInfo(data.facebookAccessToken);
    if (userProfile?.statusCode === 400) return userProfile;
    const userLogins = await db.UserLogin.findOne({
      where: {
        providerKey: userProfile?.id
      }
    })
    if (userLogins) {
      if (data.type == "login") {
        const user = await db.User.findOne({
          where: {
            id: userLogins.userId,
          },
          include: [db.UserLogin]
        })
        //truyen vao service
        const userInfoExtend = await getUserInfo(user.id, data.serviceName);
        const accessToken = createFacebookJWT(userProfile);
        const refreshToken = createRefreshToken();
        user.UserLogins.forEach(ul => {
          userInfoExtend.userLogins.push({
            loginProvider: ul.loginProvider,
            providerKey: ul.providerKey,
            providerDisplayName: ul.providerDisplayName,
            userId: ul.userId,
            accountAvatar: ul.accountAvatar,
            accountName: ul.accountName,
            isUnlink: ul.isUnlink,
          })
        })
        await db.UserToken.create({
          accessToken,
          refreshToken,
          expires: timeExpires.notRemember,
          userId: user.id
        }, { transaction: t })
        await t.commit();
        return {
          statusCode: 200,
          message: "Login successfully.",
          user: userInfoExtend,
          accessToken,
          refreshToken
        }
      }
      else {
        return {
          statusCode: 409,
          message: "Facebook account is invalid or already in use."
        }
      }
    }
    else {
      if (data.type == "login") {
        const isExistedEmail = await checkEmailExist(userProfile.email);
        if (isExistedEmail) {
          return {
            statusCode: 409,
            message: `Email ${userProfile.email} is already used by a login method other than Facebook.`
          }
        }
        const userId = uuid.v4();
        const newUserWithProvider = {
          UserId: userId,
          UserName: userProfile.email,
          Email: userProfile.email,
          BirthDate: new Date(),
          CreatedAt: new Date(),
          ModifiedAt: new Date(),
          EmailConfirm: true,
          Url: userProfile.picture.data.url,
          Avatar: "Provider Avatar"
        }
        const response = await postUserInfo(newUserWithProvider, data.serviceName)
        const newProvider = {
          userId: userId,
          loginProvider: "Facebook",
          providerKey: userProfile.id,
          providerDisplayName: "Facebook",
          accountAvatar: userProfile.picture.data.url,
          accountName: userProfile.name,
          isUnlink: false,
        }
        const service = await db.Service.findOne({
          where: {
            serviceName: data.serviceName,
          }
        })
        const accessToken = createFacebookJWT(userProfile);
        const refreshToken = createRefreshToken();
        await db.User.create({
          id: userId,
          email: newUserWithProvider.Email,
          username: newUserWithProvider.UserName,
          role: "member",
          serviceId: service.id
        }, { transaction: t });
        await db.UserLogin.create(newProvider, { transaction: t });
        const providers = await db.UserLogin.findAll({
          where: {
            userId: userId
          }
        })
        providers.forEach(ul => {
          response.userLogins.push({
            loginProvider: ul.loginProvider,
            providerKey: ul.providerKey,
            providerDisplayName: ul.providerDisplayName,
            userId: ul.userId,
            accountAvatar: ul.accountAvatar,
            accountName: ul.accountName,
            isUnlink: ul.isUnlink,
          })
        })

        await db.UserToken.create({
          accessToken,
          refreshToken,
          expires: timeExpires.notRemember,
          userId: userId
        }, { transaction: t })

        await t.commit();
        return {
          statusCode: 200,
          message: "Login successfully.",
          user: response,
          accessToken,
          refreshToken
        }
      }
      else {
        const userLink = await db.User.findOne({
          where: {
            id: data?.userId
          },
          include: [db.UserLogin]
        })
        const newProvider = {
          userId: userLink.id,
          loginProvider: "Facebook",
          providerKey: userProfile.id,
          providerDisplayName: "Facebook",
          accountAvatar: userProfile.picture.data.url,
          accountName: userProfile.name,
          isUnlink: !!userLink?.password || !!userLink.UserLogins?.length,
        }
        await db.UserLogin.create(newProvider, { transaction: t });

        const userInfoExtend = await getUserInfo(userLink.id, data.serviceName);
        userLink.UserLogins.forEach(ul => {
          userInfoExtend.userLogins.push({
            loginProvider: ul.loginProvider,
            providerKey: ul.providerKey,
            providerDisplayName: ul.providerDisplayName,
            userId: ul.userId,
            accountAvatar: ul.accountAvatar,
            accountName: ul.accountName,
            isUnlink: ul.isUnlink,
          })
        })
        userInfoExtend.userLogins.push(newProvider);

        await t.commit();
        return {
          message: "Link account successfully.",
          statusCode: 200,
          user: userInfoExtend
        }
      }
    }
  } catch (err) {
    return {
      statusCode: 500,
      message: err.message
    }
  }
}

const googleLink = async (userId, params) => {
  try {
    const provider = await getTokenGoogle(params.code);
    const providerExternalLink = await db.UserLogin.findOne({
      where: {
        providerKey: provider.providerId
      }
    })
    if (!providerExternalLink) {
      const userLink = await db.User.findOne({
        where: {
          id: userId
        },
        include: db.UserLogin
      })
      const newProvider = {
        userId: userLink.id,
        loginProvider: provider.providerName,
        providerKey: provider.providerId,
        providerDisplayName: provider.providerDisplayName,
        accountAvatar: provider.picture,
        accountName: provider.email,
        isUnlink: !!userLink?.password || !!userLink.UserLogins?.length,
      }
      await db.UserLogin.create(newProvider);

      const userInfoExtend = await getUserInfo(userLink.id, params.serviceName);
      userLink.UserLogins.forEach(ul => {
        userInfoExtend.userLogins.push({
          loginProvider: ul.loginProvider,
          providerKey: ul.providerKey,
          providerDisplayName: ul.providerDisplayName,
          userId: ul.userId,
          accountAvatar: ul.accountAvatar,
          accountName: ul.accountName,
          isUnlink: ul.isUnlink,
        })
      })
      userInfoExtend.userLogins.push(newProvider);
      return {
        message: "Link account successfully.",
        statusCode: 200,
        user: userInfoExtend
      }
    } else {
      return {
        statusCode: 409,
        message: "Google account is invalid or already in use."
      }
    }
  } catch (err) {
    console.log(err);
    return {
      statusCode: 500,
      message: err.message
    }
  }
}

const refreshToken = async (refreshToken, type, remember) => {
  const t = await sequelize.transaction();
  try {
    if (!refreshToken) {
      await t.commit();
      console.log("Cookie not contain RefreshToken");
      return {
        message: "Refresh token failed.",
        statusCode: 403
      };
    }
    const currRfToken = await db.UserToken.findOne({
      where: {
        refreshToken,
      }
    })
    if (!currRfToken || currRfToken.expires.getTime() <= Date.now()) {
      if (currRfToken) {
        console.log("RefreshToken was expired");
        await db.UserToken.destroy({
          where: {
            refreshToken: currRfToken.refreshToken,
          },
          transaction: t
        });
      }
      await t.commit();
      console.log("Not found RefreshToken in DB", refreshToken, currRfToken);
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

    const userInfoExtend = await getUserInfo(user.id, user.Service.serviceName)
    if (userInfoExtend.isActive) {
      await t.commit();
      return {
        isBan: true,
        statusCode: 403,
        message: "Your account has been banned. Please contact admin@gmail.com for more details."
      }
    }

    let expired;
    let newAccessToken;
    let newRefreshToken;
    const payload = getListClaim(user);
    if (type === 'facebook') {
      expired = timeExpires.notRemember;
      newAccessToken = createFacebookJWT(payload);
      newRefreshToken = createRefreshToken();
    } else if (type === 'default') {
      expired = remember === "false" ? timeExpires.notRemember : timeExpires.remember;
      newAccessToken = createJWT(payload);
      newRefreshToken = createRefreshToken();
    }
    else {
      const { data: { id_token, access_token } } = await axios.post(`${process.env.GOOGLE_TOKEN_URI}/token`, null, {
        params: {
          client_id: process.env.CLIENT_ID,
          client_secret: process.env.CLIENT_SECRET,
          grant_type: "refresh_token",
          refresh_token: currRfToken.refreshToken,
          scope: "openid profile email",
        }
      });

      expired = timeExpires.notRemember;
      newAccessToken = id_token;
      newRefreshToken = currRfToken.refreshToken;
    }
    console.log("new refresh_token", newRefreshToken);
    await db.UserToken.update(
      {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expires: expired,
        updatedAt: new Date(),
      },
      {
        where: {
          userId: user.id,
        },
        transaction: t
      },
    );
    await t.commit();
    return {
      user,
      message: "Refresh token successfully.",
      statusCode: 200,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    }
  } catch (error) {
    await t.rollback();
    console.log(error);
    return {
      statusCode: 500,
      message: "Refresh token failed."
    }
  }
}

export { postLogout, registerUser, postLogin, refreshToken, loginGoogle, loginFacebook, googleLink, getUserInfo, unlinkGoogle, confirmEmail, forgotPassword, resetPassword, changePassword, enableF2A, verifyOtp }