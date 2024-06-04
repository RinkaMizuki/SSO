require("dotenv").config();
import express from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import routes from "./routes";
import cors from "cors";
import { corsOptions } from "./configs/cors";
import connectionRedis from "./configs/connectRedis";

//create instance app
const app = express()
const PORT = process.env.PORT || 8081;
//config cors
app.use(cors(corsOptions))

//config body-parser
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

//config cookie-parser
app.use(cookieParser());

//config session
// configSession(app);

app.use(routes)

connectionRedis();
// configPassport();

app.listen(PORT, () => {
  console.log(">>> SSO Backend is running on the port = " + PORT);
})