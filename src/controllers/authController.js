import { confirmEmail, enableF2A, forgotPassword, googleLink, loginFacebook, loginGoogle, loginUser, postLogout, refreshToken, registerUser, resetPassword, unlinkGoogle, verifyOtp } from "../services/authService";
import { certs, verifyFacebookJWT, verifyGoogleJWT, verifyJWT } from "../services/jwtService";

function setCookie(res, data, cookieATage, cookieRTage) {
  res.cookie("accessToken", data.accessToken,
    {
      maxAge: cookieATage,
      httpOnly: true,
    }
  )
  res.cookie("refreshToken", data.refreshToken,
    {
      maxAge: cookieRTage,
      httpOnly: true,
    }
  )
  delete data["accessToken"]
  delete data["refreshToken"]
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
      remember: req.body.remember
    }
    const result = await loginUser(loginData);
    if (result.statusCode === 200) {
      const rtExpiresTime = !loginData.remember ? 2 * 60 * 60 * 1000 : 30 * 24 * 60 * 60 * 1000;
      setCookie(res, result, 1 * 60 * 60 * 1000, rtExpiresTime);
    }
    res.status(result.statusCode).json(result);
  },
  postRegister: async function (req, res, next) {
    const origin = req.headers.origin; // hostname = 'localhost:5000'
    const data = {
      email: req.body.email,
      username: req.body.username,
      password: req.body.password,
      serviceName: req.body.service,
      serviceUrl: origin + "/",
    }
    const result = await registerUser(data);
    return res.status(result.statusCode).json(result);
  },
  postForgotPassword: async function (req, res, next) {
    const data = {
      email: req.body?.email,
      returnUrl: req.body?.returnUrl
    }
    if (!data.email || !data.returnUrl) {
      return res.status(400).json({
        statusCode: 400,
        message: "Invalid returnUrl or email."
      });
    }
    const result = await forgotPassword(data);
    res.status(result.statusCode).json(result);
  },
  postResetPassword: async function (req, res, next) {
    const data = {
      password: req.body?.password,
      token: req.body?.token
    }
    const result = await resetPassword(data);
    res.status(result.statusCode).json(result);
  },
  getConfirmEmail: async function (req, res, next) {
    const data = {
      email: req.query?.email,
      token: req.query?.token,
    }
    if (!data.email || !data.token) {
      return res.status(400).json({
        statusCode: 400,
        message: "Invalid email or token."
      });
    }
    const result = await confirmEmail(data);
    res.status(result.statusCode).json(result);
  },
  getEnableF2A: async function (req, res, next) {
    const data = {
      phone: req.query?.phone,
    }
    const result = await enableF2A(data);
    res.status(result.statusCode).json(result);
  },
  postVerifyOtp: async function (req, res, next) {
    const data = req.body;
    const result = await verifyOtp(data);
    res.status(result.statusCode).json(result);
  },
  postLogout: async function (req, res, next) {
    const rfToken = req.cookies?.refreshToken;
    const acToken = req.cookies?.accessToken;
    const userId = req.body?.userId;
    const result = await postLogout(rfToken, acToken, userId);
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
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
      setCookie(res, result, 5 * 60 * 1000, 10 * 60 * 1000);
    }
    res.status(result.statusCode).json(result);
  },
  postFacebookLogin: async function (req, res, next) {
    const params = {
      type: req.query.type,
      userId: req.query?.userId,
      facebookAccessToken: req.query.facebookAccessToken,
      serviceName: req.query.serviceName
    }
    const data = await loginFacebook(params);
    if (data.statusCode === 200 && params.type === "login") {
      setCookie(res, data, 2 * 60 * 1000, 10 * 60 * 1000);
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
      providerId: req.query?.providerId
    }
    const result = await unlinkGoogle(data);
    res.status(result.statusCode).json(result);
  },
  postVerifyToken: async function (req, res, next) {
    let accessToken = req.header('authorization')?.split(' ')[1];
    if (!accessToken) accessToken = req.cookies?.accessToken;
    const result = verifyJWT(accessToken);
    res.status(result.statusCode).json(result);
  },
  postVerifyFacebookToken: async function (req, res, next) {
    let fbAccessToken = req.header('authorization')?.split(' ')[1];
    if (!fbAccessToken) fbAccessToken = req.cookies?.accessToken;
    const result = verifyFacebookJWT(fbAccessToken);
    res.status(result.statusCode).json(result);
  },
  postVerifyGoogleToken: async function (req, res, next) {
    let ggAccessToken = req.header('authorization')?.split(' ')[1];
    if (!ggAccessToken) ggAccessToken = req.cookies?.accessToken;
    const result = await verifyGoogleJWT(ggAccessToken);
    res.status(result?.statusCode).json(result);
  },
  getRefreshToken: async function (req, res, next) {
    const rfToken = req.cookies?.refreshToken;
    const result = await refreshToken(rfToken, req.query.type);
    if (result.statusCode === 200) {
      setCookie(res, result, 60000, 10 * 60 * 1000);
    }
    res.status(result.statusCode).json(result);
  },
  getCerts: async function (req, res, next) {
    const result = certs();
    res.status(200).json(result);
  }
}
