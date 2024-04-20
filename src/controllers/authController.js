import passport from "passport";
import { loginFacebook, loginUser, postLogout, refreshToken, registerUser } from "../services/authService";
import { verifyFacebookJWT, verifyGoogleJWT, verifyJWT } from "../services/jwtService";

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
    }
    const result = await loginUser(loginData);
    if (result.statusCode === 200) {
      setCookie(res, result, 2 * 60 * 1000, 10 * 60 * 1000);
    }
    res.status(result.statusCode).json(result);
  },
  postRegister: async function (req, res, next) {
    const origin = req.headers.origin; // hostname = 'localhost:8080'
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
  postLogout: async function (req, res, next) {
    const rfToken = req.cookies?.refreshToken;
    const result = await postLogout(rfToken);
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

  },
  deleteUnlinkProvider: async function (req, res, next) {

  },
  postVerifyToken: async function (req, res, next) {
    let accessToken = req.header('authorization')?.split(' ')[1];
    if (!accessToken) accessToken = req.cookies?.accessToken;
    const result = verifyJWT(accessToken);
    return res.status(result.statusCode).json(result);
  },
  postVerifyFacebookToken: async function (req, res, next) {
    let fbAccessToken = req.header('authorization')?.split(' ')[1];
    if (!fbAccessToken) fbAccessToken = req.cookies?.accessToken;
    const result = verifyFacebookJWT(fbAccessToken);
    return res.status(result.statusCode).json(result);
  },
  postVerifyGoogleToken: async function (req, res, next) {
    let ggAccessToken = req.header('authorization')?.split(' ')[1];
    if (!ggAccessToken) ggAccessToken = req.cookies?.accessToken;
    const result = verifyGoogleJWT(ggAccessToken);
    return res.status(result.statusCode).json(result);
  },
  getRefreshToken: async function (req, res, next) {
    const rfToken = req.cookies?.refreshToken;
    const result = await refreshToken(rfToken, req.query.type);
    if (result.statusCode === 200) {
      setCookie(res, result, 60000, 10 * 60 * 1000);
    }
    return res.status(result.statusCode).json(result);
  }
}
