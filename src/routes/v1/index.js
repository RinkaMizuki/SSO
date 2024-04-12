import authRoutes from "./auth.route";
import express from "express";

const routesV1 = express.Router();

routesV1.use('/auth', authRoutes);

export default routesV1;