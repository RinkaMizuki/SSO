import express from "express";
import routesV1 from "./v1";
import { authMiddleware } from "../middlewares/authMiddleware";

const routes = express.Router();

routes.use('/v1', authMiddleware, routesV1);
routes.use('/', authMiddleware, (req, res) => {
  res.render('home')
})
routes.use((req, res) => {
  return res.send('404 not found')
})

export default routes;