const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true, // Use `true` for port 465, `false` for all other ports
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD,
  },
});

const createMailToken = (payload, expires) => {
  return jwt.sign(payload, process.env.SECRET, {
    algorithm: 'HS256',
    expiresIn: expires,
    issuer: process.env.ISSUER,
    audience: process.env.AUDIENCE,
  })
}

async function sendMailAsync(to, subject, html) {
  // send mail with defined transport object
  const info = await transporter.sendMail({
    from: '"Rinka 👻" <nguyenduc09012003@gmail.com>', // sender address
    to, // list of receivers
    subject, // Subject line
    html, // html body
  });

  console.log("Message sent: %s", info.messageId);
  // Message sent: <d786aa62-4e0a-070a-47ed-0b0666549519@ethereal.email>
}
export { sendMailAsync, createMailToken }