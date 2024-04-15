import jwt from "jsonwebtoken";
const uuid = require('uuid');

const createJWT = (payload) => {
  return jwt.sign(payload, process.env.SECRET, {
    algorithm: 'HS256',
    expiresIn: process.env.EXPIRES,
    issuer: process.env.ISSUER,
    audience: process.env.AUDIENCE,
  })
}
const verifyJWT = (token) => {
  const secret = process.env.SECRET;
  try {
    const decoded = jwt.verify(token, secret);
    return { statusCode: 200, message: "Verify successfully.", token };
  } catch (error) {
    return {
      statusCode: 401,
      message: error.message
    };
  }
}

const verifyPermission = (data) => {
  return {
    statusCode: 200,
    message: "Verify permission passed.",
  }
}

const createRefreshToken = () => {
  return uuid.v4();
}

export {
  createJWT,
  verifyJWT,
  createRefreshToken,
  verifyPermission
}