import session from "express-session";
import Sequelize from "sequelize";
import connectSessionSequelize from "connect-session-sequelize";
import passport from "passport";
require("dotenv").config();

const configSession = (app) => {
  const SequelizeStore = connectSessionSequelize(session.Store);

  // create database, ensure 'sqlite3' in your package.json
  const sequelize = new Sequelize(process.env.DATABASE, process.env.ROOT, process.env.PASSWORD, {
    host: process.env.HOST,
    dialect: process.env.DIALECT,
    logging: false,
  });
  const myStore = new SequelizeStore({
    db: sequelize,
    checkExpirationInterval: 60 * 1000
  });
  // configure express
  app.use(
    session({
      secret: process.env.SESSIONKEY,//encode sid key
      store: myStore,
      saveUninitialized: false,
      resave: false, // we support the touch method so per the express-session docs this should be set to false
      proxy: true, // if you do SSL outside of node.
      cookie: {
        sameSite: "strict",
        httpOnly: true,
        maxAge: 60 * 1000,
      }
    })
  );
  myStore.sync();

  app.use(passport.authenticate('session'));

  passport.serializeUser(function (user, cb) {
    console.log("save user:::", user);
    process.nextTick(function () {
      return cb(null, user);
    });
  });

  passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
      return cb(null, user);
    });
  });
}

export default configSession;