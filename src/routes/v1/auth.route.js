import express from "express";
import { authController } from "../../controllers/v1/authController";
import { adminMiddleware } from "../../middlewares/authMiddleware";

const authRoutes = express.Router();

authRoutes.post('/login', authController.postLogin)

authRoutes.post('/login-admin', adminMiddleware, authController.postLogin)

authRoutes.post('/register', authController.postRegister)

authRoutes.post('/logout', authController.postLogout)

authRoutes.post('/forgot-password', authController.postForgotPassword)

authRoutes.post('/reset-password', authController.postResetPassword)

authRoutes.post('/change-password', authController.postChangePassword)

authRoutes.get('/refresh-token', authController.getRefreshToken)

authRoutes.post('/verify-token', authController.postVerifyToken)

authRoutes.post('/verify-facebook-token', authController.postVerifyFacebookToken)

authRoutes.post('/verify-google-token', authController.postVerifyGoogleToken)

authRoutes.post('/google-login', authController.postGoogleLogin)

authRoutes.post('/facebook-login', authController.postFacebookLogin)

authRoutes.post('/google-link', authController.postGoogleLink)

authRoutes.delete('/unlink-provider', authController.deleteUnlinkProvider)

authRoutes.get('/confirm-email', authController.getConfirmEmail)

authRoutes.get('/enable-f2a', authController.getEnableF2A)

authRoutes.post('/verify-otp', authController.postVerifyOtp)

export default authRoutes;