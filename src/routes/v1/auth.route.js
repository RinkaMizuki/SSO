import express from "express";
import { authController } from "../../controllers/authController";

const authRoutes = express.Router();

authRoutes.post('/login', authController.postLogin)

authRoutes.post('/register', authController.postRegister)

authRoutes.post('/logout', authController.postLogout)

authRoutes.get('/refresh-token', authController.getRefreshToken)

authRoutes.post('/verify-token', authController.postVerifyToken)

authRoutes.post('/verify-facebook-token', authController.postVerifyFacebookToken)

authRoutes.post('/verify-google-token', authController.postVerifyGoogleToken)

authRoutes.post('/google-login', authController.postGoogleLogin)

authRoutes.post('/facebook-login', authController.postFacebookLogin)

authRoutes.post('/google-link', authController.postGoogleLink)

authRoutes.delete('/unlink-provider', authController.deleteUnlinkProvider)

export default authRoutes;