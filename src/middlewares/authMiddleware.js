import { Op } from "sequelize";
import db from "../models/index";
const adminMiddleware = async (req, res, next) => {
  try {
    const username = req.body.username;
    const user = await db.User.findOne({
      where: {
        [Op.and]: [
          {
            [Op.or]: [
              { email: username },
              { username: username }
            ]
          },
          { emailConfirm: true }
        ],
      },
      include: [db.Service, db.UserLogin]
    });
    if (!user || user.role === "admin") {
      return next();
    }
    return res.status(403).json({
      statusCode: 403,
      message: "You enough permission to access the resource."
    })
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      statusCode: 500,
      message: "Internal Server Error."
    })
  }
}

export { adminMiddleware }