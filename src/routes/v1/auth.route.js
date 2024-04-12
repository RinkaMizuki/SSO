import express from "express";
import passport from "passport";
import { authController } from "../../controllers/authController";

const authRoutes = express.Router();

authRoutes.get('/login', authController.getLoginPage)

authRoutes.post('/login', passport.authenticate('local', {
  successRedirect: "/",
  failureRedirect: "/login"
}))

authRoutes.get('/register', authController.getRegisterPage)

authRoutes.post('/register', authController.postRegister)

authRoutes.post('/logout', authController.postLogout)

export default authRoutes;