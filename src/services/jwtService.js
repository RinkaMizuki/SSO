import axios from "axios";
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
    jwt.verify(token, secret, {
      issuer: process.env.ISSUER,
      audience: process.env.AUDIENCE,
    });
    return { statusCode: 200, message: "Verify successfully.", token };
  } catch (error) {
    return {
      statusCode: 401,
      message: error.message
    };
  }
}

const verifyFacebookJWT = (fbToken) => {
  const secret = process.env.FB_APP_SECRET;
  try {
    jwt.verify(fbToken, secret, {
      audience: process.env.FB_APP_ID,
      issuer: process.env.FB_ISSUER,
    });
    return { statusCode: 200, message: "Verify successfully.", fbToken };
  } catch (error) {
    return {
      statusCode: 401,
      message: error.message
    };
  }
}
const getGoogleCertificates = async () => {
  try {
    const response = await axios.get('https://www.googleapis.com/oauth2/v1/certs');
    return response.data;
  } catch (error) {
    console.error('Error fetching Google certificates:', error);
    throw error;
  }
};

const verifyGoogleJWT = async (ggToken) => {
  try {
    const certificates = await getGoogleCertificates();

    const headerKid = payload.header.kid;
    const certificate = certificates[headerKid];
    console.log(certificate);
    jwt.verify(ggToken, certificate, {
      audience: process.env.CLIENT_ID,
      issuer: process.env.CLIENT_ISSUER,
    });
    return { statusCode: 200, message: "Verify successfully.", ggToken };
  } catch (error) {
    return {
      statusCode: 401,
      message: error.message
    };
  }
}

const createFacebookJWT = (payload) => {
  return jwt.sign(payload, process.env.FB_APP_SECRET, {
    algorithm: 'HS256',
    expiresIn: process.env.EXPIRES,
    issuer: process.env.FB_ISSUER,
    audience: process.env.FB_APP_ID,
  })
}

const createRefreshToken = () => {
  return uuid.v4();
}

export {
  createJWT,
  verifyJWT,
  verifyGoogleJWT,
  verifyFacebookJWT,
  createFacebookJWT,
  createRefreshToken
}