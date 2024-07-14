//list domain allowed by pass cors policy
const whitelist = [
  "http://localhost:5000",
  "http://localhost:5083",
  "http://localhost:5173",
];
export const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) {
      //for bypassing postman req with  no origin
      return callback(null, true);
    }
    if (whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS policy."));
    }
  },
  credentials: true,
  optionSuccessStatus: 200,
};
