import jwt from "jsonwebtoken";
const uuid = require("uuid");
//const { OAuth2Client } = require("google-auth-library");

const createJWT = (payload) => {
    return jwt.sign(payload, process.env.SECRET, {
        algorithm: "HS256",
        expiresIn: +process.env.EXPIRES,
        issuer: process.env.ISSUER,
        audience: process.env.AUDIENCE,
    });
};

const createRefreshToken = () => {
    return uuid.v4();
};

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
            message: error.message,
        };
    }
};

// const createFacebookJWT = (payload) => {
//     return jwt.sign(payload, process.env.FB_APP_SECRET, {
//         algorithm: "HS256",
//         expiresIn: +process.env.EXPIRES,
//         issuer: process.env.FB_ISSUER,
//         audience: process.env.FB_APP_ID,
//     });
// };

// const verifyFacebookJWT = (fbToken) => {
//     const secret = process.env.FB_APP_SECRET;
//     try {
//         jwt.verify(fbToken, secret, {
//             audience: process.env.FB_APP_ID,
//             issuer: process.env.FB_ISSUER,
//         });
//         return {
//             statusCode: 200,
//             message: "Verify token successfully.",
//             token: fbToken,
//         };
//     } catch (error) {
//         return {
//             statusCode: 401,
//             message: error.message,
//         };
//     }
// };

// const verifyGoogleJWT = async (ggToken) => {
//     try {
//         const client = new OAuth2Client();
//         await client.verifyIdToken({
//             idToken: ggToken,
//             audience: process.env.CLIENT_ID,
//         });
//         return {
//             statusCode: 200,
//             message: "Verify token successfully.",
//             token: ggToken,
//         };
//     } catch (error) {
//         return {
//             statusCode: 401,
//             message: error.message,
//         };
//     }
// };

export {
    createJWT,
    verifyJWT,
    createRefreshToken,
    //verifyGoogleJWT,
    //verifyFacebookJWT,
    //createFacebookJWT,
};
