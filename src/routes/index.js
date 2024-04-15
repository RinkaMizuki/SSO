import express from "express";
import routesV1 from "./v1";
// import { authMiddleware } from "../middlewares/authMiddleware";

const routes = express.Router();

routes.use('/api/v1', routesV1);

routes.use((req, res) => {
  return res.status(404).json({
    message: "404 Not Found",
    statusCode: 404
  });
})

export default routes;