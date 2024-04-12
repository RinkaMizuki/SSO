import { registerUser } from "../services/authService";

export const authController = {
  getLoginPage: async function (req, res, next) {
    const data = req.flash('data');
    res.render('login', { title: 'Login Page', message: data[0] || "", code: data[1], usernameInput: data[2] });
  },
  getRegisterPage: async function (req, res, next) {
    res.render('register', { title: "Register Page" })
  },
  postRegister: async function (req, res, next) {
    const data = {
      email: req.body.email,
      username: req.body.username,
      password: req.body.password
    }
    const result = await registerUser(data);
    if (result.statusCode === 200) {
      return res.redirect('/v1/auth/login')
    }
    return res.redirect('/v1/auth/register')
  },
  postLogout: async function (req, res, next) {
    req.logout(function (err) {
      if (err) { return next(err); }
      req.session.destroy(function (err) {
        if (!err) {
          res.clearCookie('connect.sid', { path: '/' });
          res.redirect('/');
        }
        else {
          console.log(err);
        }
      })
    });
  }
}
