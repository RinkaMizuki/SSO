require("dotenv").config();
import express from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
const path = require('path');
import routes from "./routes";
import { corsOptions } from "./configs/cors";
import { configPassport } from "./configs/passport";
import configSession from "./configs/session";
import flash from "connect-flash";

//create instance app
const app = express()
const PORT = process.env.PORT || 8081;
//config flash
app.use(flash());

//set template engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
//config cors
// app.use(cors(corsOptions))

//config body-parser
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

//config cookie-parser
app.use(cookieParser());

//config session
configSession(app);

app.use(routes)

configPassport();

app.listen(PORT, () => {
  console.log(">>> SSO Backend is running on the port = " + PORT);
})