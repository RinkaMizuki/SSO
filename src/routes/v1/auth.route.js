import express from "express";
import { authController } from "../../controllers/authController";
import { getUserInfo, loginGoogle } from "../../services/authService";

const authRoutes = express.Router();

authRoutes.post('/login', authController.postLogin)

authRoutes.post('/register', authController.postRegister)

authRoutes.post('/logout', authController.postLogout)

authRoutes.get('/refresh-token', authController.getRefreshToken)

authRoutes.post('/verify-token', authController.postVerifyToken)

authRoutes.post('/google-login', authController.postGoogleLogin)

authRoutes.post('facebook-login', authController.postFacebookLogin)

authRoutes.post('/google-link', authController.postGoogleLink)

authRoutes.delete('/unlink-provider', authController.deleteUnlinkProvider)

authRoutes.get('/user-info', async function (req, res) {
  await loginGoogle({
    email: "asd@gmail.com",
    providerId: "123123"
  })
})

export default authRoutes;