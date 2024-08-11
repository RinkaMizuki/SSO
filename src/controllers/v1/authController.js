import {
  changePassword,
  confirmEmail,
  enableF2A,
  forgotPassword,
  googleLink,
  loginFacebook,
  loginGoogle,
  postLogin,
  postLogout,
  refreshToken,
  registerUser,
  resetPassword,
  unlinkGoogle,
  verifyOtp,
} from "../../services/authService";
import { verifyJWT } from "../../services/jwtService";
import { cookieExpires } from "../../services/timeExpires";

function setCookie(res, data, cookieRTage) {
  res.cookie("refreshToken", data.refreshToken, {
    maxAge: cookieRTage,
    httpOnly: true,
  });
  if (data.user?.role !== "admin") {
    res.cookie("accessToken", data.accessToken, {
      maxAge: cookieRTage,
      //httpOnly: true,
    });
    delete data["accessToken"];
  }
  delete data["refreshToken"];
}

export const authController = {
  postLogin: async function (req, res, next) {
    // passport.authenticate('local', function (error, user, info) {
    //   if (error) {
    //     return res.status(500).json(error);
    //   }
    //   if (!user) {
    //     return res.status(404).json(info);
    //   }
    //   req.login(user, function (err) {
    //     if (err) return next(err);
    //     setCookie(res, user.user, 2 * 60 * 1000, 10 * 60 * 1000);
    //     res.status(200).json(user);
    //   })
    // })(req, res, next);
    const loginData = {
      valueLogin: req.body.username,
      password: req.body.password,
      remember: req.body.remember,
    };
    const result = await postLogin(loginData);
    if (result.statusCode === 200) {
      const rtExpiresTime = !loginData.remember
        ? cookieExpires.rfTokenNotRemember
        : cookieExpires.rfTokenRemember;
      setCookie(res, result, rtExpiresTime);
    }
    res.status(result.statusCode).json(result);
  },
  postRegister: async function (req, res, next) {
    const data = {
      email: req.body.email,
      username: req.body.username,
      password: req.body.password,
      serviceName: req.body.serviceName,
      serviceUrl: req.body.serviceUrl,
    };
    const result = await registerUser(data);
    return res.status(result.statusCode).json(result);
  },
  postForgotPassword: async function (req, res, next) {
    const data = {
      email: req.body?.email,
      returnUrl: req.body?.returnUrl,
    };
    if (!data?.email || !data.returnUrl) {
      return res.status(400).json({
        statusCode: 400,
        message: "Invalid returnUrl or email.",
      });
    }
    const result = await forgotPassword(data);
    res.status(result.statusCode).json(result);
  },
  postResetPassword: async function (req, res, next) {
    const data = {
      password: req.body?.password,
      token: req.body?.token,
    };
    const result = await resetPassword(data);
    res.status(result.statusCode).json(result);
  },

  postChangePassword: async function (req, res, next) {
    const data = {
      currentPassword: req.body?.currentPassword,
      newPassword: req.body?.newPassword,
      userId: req.body?.userId,
    };
    console.log(data);
    const result = await changePassword(data);
    res.status(result.statusCode).json(result);
  },

  getConfirmEmail: async function (req, res, next) {
    const data = {
      email: req.query?.email,
      token: req.query?.token,
      serviceName: req.query?.serviceName,
    };
    if (!data.email || !data.token) {
      return res.status(400).json({
        statusCode: 400,
        message: "Invalid email or token.",
      });
    }
    if (!data.serviceName) {
      return res.status(400).json({
        statusCode: 400,
        message: "ServiceName not provice.",
      });
    }
    const result = await confirmEmail(data);
    res.status(result.statusCode).json(result);
  },
  getEnableF2A: async function (req, res, next) {
    const data = {
      phone: req.query?.phone,
    };
    const result = await enableF2A(data);
    res.status(result.statusCode).json(result);
  },
  postVerifyOtp: async function (req, res, next) {
    const data = req.body;
    const type = req.query?.type;
    const result = await verifyOtp(data, type);
    res.status(result.statusCode).json(result);
  },
  postLogout: async function (req, res, next) {
    const rfToken = req.cookies?.refreshToken;
    const acToken = req.cookies?.accessToken;
    const userId = req.body?.userId;
    const result = await postLogout(rfToken, acToken, userId);
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    return res.status(result.statusCode).json(result);
    // req.logout(function (err) {
    //   if (err) { return next(err); }
    //   req.session.destroy(function (err) {
    //     if (!err) {
    //       res.clearCookie('connect.sid', { path: '/' });
    //       return res.status(200).json({
    //         message: "Logout successfully.",
    //         statusCode: 200
    //       })
    //     }
    //     else {
    //       console.log(err);
    //       return res.status(400).json({
    //         message: "Logout failed.",
    //         statusCode: 400
    //       })
    //     }
    //   })
    // });
  },
  postGoogleLogin: async function (req, res, next) {
    const data = req.body;
    const result = await loginGoogle(data);
    if (result.statusCode === 200) {
      setCookie(res, result, cookieExpires.rfTokenNotRemember);
    }
    res.status(result.statusCode).json(result);
  },
  postFacebookLogin: async function (req, res, next) {
    const params = {
      type: req.query.type,
      userId: req.query?.userId,
      facebookAccessToken: req.query.facebookAccessToken,
      serviceName: req.query.serviceName,
    };
    const data = await loginFacebook(params);
    if (data.statusCode === 200 && params.type === "login") {
      setCookie(res, data, cookieExpires.rfTokenNotRemember);
    }
    res.status(data.statusCode).json(data);
  },
  postGoogleLink: async function (req, res, next) {
    const userId = req.query.userId;
    const data = req.body;
    const result = await googleLink(userId, data);
    res.status(result.statusCode).json(result);
  },

  deleteUnlinkProvider: async function (req, res, next) {
    const data = {
      userId: req.query?.userId,
      providerId: req.query?.providerId,
    };
    const result = await unlinkGoogle(data);
    res.status(result.statusCode).json(result);
  },
  postVerifyToken: async function (req, res, next) {
    let accessToken = req.header("authorization")?.split(" ")[1];
    if (!accessToken) accessToken = req.cookies?.accessToken;
    const result = verifyJWT(accessToken);
    res.status(result.statusCode).json(result);
  },
  getRefreshToken: async function (req, res, next) {
    const rfToken = req.cookies?.refreshToken;
    const remember = !!req.query?.remember;
    const result = await refreshToken(rfToken, remember);
    if (result.statusCode === 200) {
      const rtExpiresTime =
        remember === "false"
          ? cookieExpires.rfTokenNotRemember
          : cookieExpires.rfTokenRemember;
      setCookie(res, result, rtExpiresTime);
    }
    delete result["user"];
    res.status(result.statusCode).json(result);
  },
};
