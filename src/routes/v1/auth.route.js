import express from "express";
import { authController } from "../../controllers/authController";
import { authMiddleware } from "../../middlewares/authMiddleware";

const authRoutes = express.Router();

authRoutes.post('/login', authController.postLogin)

authRoutes.post('/register', authController.postRegister)

authRoutes.post('/logout', authController.postLogout)

authRoutes.get('/refresh-token', authController.getRefreshToken)

authRoutes.post('/verify-token', authController.postVerifyToken)

authRoutes.post('/verify-permission', authController.postVerifyPermission)

export default authRoutes;