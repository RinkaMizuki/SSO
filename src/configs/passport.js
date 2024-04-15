import passport from "passport";
import LocalStrategy from "passport-local";
import { loginUser } from "../services/authService";

export const configPassport = () => {
  passport.use(new LocalStrategy(
    { passReqToCallback: true },
    async function verify(req, username, password, done) {
      const loginData = {
        valueLogin: username,
        password,
      }
      const result = await loginUser(loginData);
      if (result && result.statusCode === 200) {
        return done(null, result)
      }
      else {
        return done(null, false, result)
      }
    }));
}