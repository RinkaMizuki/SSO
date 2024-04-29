import express from "express";

const authRoutes = express.Router();

authRoutes.get('/auth', function (req, res, next) {
  res.send('Hello World v2 !!')
})

export default authRoutes;