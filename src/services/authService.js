import db from "../models/index";
import bcrypt from "bcryptjs";
require("dotenv").config();
import { Op } from "sequelize";
import { createFacebookJWT, createJWT, createRefreshToken } from "./jwtService";
const uuid = require('uuid');
import axios from "axios";

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
  }
}
const postUserInfo = async (data, userService) => {
  try {
    const httpRequest = axios.create({
      baseURL: userService === "Ecommerce" ? process.env.ECOMMERCE_BASE_URL : "",
    })
    const response = await httpRequest.post('api/v1/Admin/users/post', data);
    return response.data;
  } catch (err) {
    console.log(err);
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
const postLogout = async (rt, at, userId) => {
  try {
    if (!rt && !userId && !at) {
      return {
        statusCode: 200,
        message: "Logged out successfully."
      }
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
        const userInfo = await getUserInfo(user.id, user.Service.serviceName);
        const payload = getListClaim(user);
        const token = createJWT(payload);
        const refreshToken = createRefreshToken();

        await db.UserToken.create({
          accessToken: token,
          refreshToken,
          expires: new Date(new Date().setMinutes(new Date().getMinutes() + 10)),
          userId: user.id
        })
        return {
          user: userInfo,
          accessToken: token,
          refreshToken,
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
        expires: new Date(new Date().setMinutes(new Date().getMinutes() + 10)),
        userId: user.id
      })

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
        isUnlink: !!userLink.password || !!userLink.UserLogins.length,
      }
      await db.UserLogin.create(newProvider);
      const user = await db.User.findOne({
        where: {
          id: newProvider.userId
        },
        include: [db.UserLogin]
      })
      await db.UserToken.create({
        accessToken: data.accessToken,
        refreshToken: data.refreshToken,
        expires: new Date(new Date().setMinutes(new Date().getMinutes() + 10)),
        userId: user.id
      })

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
      return {
        statusCode: 200,
        message: "Login successfully.",
        user: userInfoExtend,
        accessToken: data.accessToken,
        refreshToken: data.refreshToken,
      }
    } else {
      const newUserWithProvider = {
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
        userId: response.id,
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
        email: newUserWithProvider.Email,
        username: newUserWithProvider.UserName,
        role: "member",
        serviceId: service.id
      });
      await db.UserLogin.create(newProvider);
      const providers = await db.UserLogin.findAll({
        where: {
          userId: response.id
        }
      })

      await db.UserToken.create({
        accessToken: data.accessToken,
        refreshToken: data.refreshToken,
        expires: new Date(new Date().setMinutes(new Date().getMinutes() + 10)),
        userId: response.id
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
    return {
      statusCode: 500,
      message: error.message
    }
  }
}

const loginFacebook = async (data) => {
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
          expires: new Date(new Date().setMinutes(new Date().getMinutes() + 10)),
          userId: user.id
        })
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
        const newUserWithProvider = {
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
          userId: response.id,
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
          email: newUserWithProvider.Email,
          username: newUserWithProvider.UserName,
          role: "member",
          serviceId: service.id
        });
        await db.UserLogin.create(newProvider);
        const providers = await db.UserLogin.findAll({
          where: {
            userId: response.id
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
          expires: new Date(new Date().setMinutes(new Date().getMinutes() + 10)),
          userId: response.id
        })
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
            id: +data?.userId
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
          isUnlink: !!userLink.password || !!userLink.UserLogins.length,
        }
        await db.UserLogin.create(newProvider);

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
        isUnlink: !!userLink.password || !!userLink.UserLogins.length,
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

const refreshToken = async (refreshToken, type) => {
  if (!refreshToken) {
    return {
      message: "Refresh token failed",
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
      await db.UserToken.destroy({
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
  let newAccessToken;
  let newRefreshToken;
  const payload = getListClaim(user);
  if (type === 'facebook') {
    newAccessToken = createFacebookJWT(payload);
    newRefreshToken = createRefreshToken();
  } else if (type === 'default') {
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
    newAccessToken = id_token;
    newRefreshToken = currRfToken.refreshToken;
  }
  await db.UserToken.update(
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

export { postLogout, registerUser, loginUser, refreshToken, loginGoogle, loginFacebook, googleLink, getUserInfo }