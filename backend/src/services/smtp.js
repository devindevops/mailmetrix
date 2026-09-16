const nodemailer = require("nodemailer");

const required = (value) =>
  typeof value === "string" && value.trim().length > 0;

const requiredPort = (value) =>
  value !== undefined &&
  value !== null &&
  String(value).trim().length > 0;

async function testSMTP(data = {}) {
  const {
    smtpHost,
    smtpPort,
    smtpSecure,
    smtpUser,
    smtpPassword,
    fromEmail,
    fromName,
    recipientName,
    recipientEmail,
    subject,
    message
  } = data;

  const requiredFields = [
    [smtpHost, "SMTP host is required"],
    [smtpUser, "SMTP username is required"],
    [smtpPassword, "SMTP password is required"],
    [fromEmail, "From email is required"],
    [recipientEmail, "Recipient email is required"],
    [message, "Message is required"]
  ];

  for (const [value, error] of requiredFields) {
    if (!required(value)) {
      return {
        httpStatus: 400,
        body: {
          success: false,
          stage: "validation",
          error
        }
      };
    }
  }

  if (!requiredPort(smtpPort)) {
    return {
      httpStatus: 400,
      body: {
        success: false,
        stage: "validation",
        error: "SMTP port is required"
      }
    };
  }

  const port = Number(smtpPort);
  const secure = smtpSecure === true || smtpSecure === "true";

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return {
      httpStatus: 400,
      body: {
        success: false,
        stage: "validation",
        error: "Invalid SMTP port"
      }
    };
  }

  const smtp = {
    host: smtpHost.trim(),
    port,
    secure,
    username: smtpUser.trim(),
    fromEmail: fromEmail.trim()
  };

  const transporter = nodemailer.createTransport({
    host: smtp.host,
    port: smtp.port,
    secure: smtp.secure,
    auth: {
      user: smtp.username,
      pass: smtpPassword
    },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000
  });

  try {
    await transporter.verify();
  } catch (error) {
    return {
      httpStatus: 401,
      body: {
        success: false,
        stage: "smtp_authentication",
        error: error.message,
        code: error.code || null,
        command: error.command || null,
        response: error.response || null,
        responseCode: error.responseCode || null,
        smtp
      }
    };
  }

  try {
    const info = await transporter.sendMail({
      from: {
        name: required(fromName) ? fromName.trim() : "MailProbe",
        address: smtp.fromEmail
      },
      to: required(recipientName)
        ? `"${recipientName.trim()}" <${recipientEmail.trim()}>`
        : recipientEmail.trim(),
      subject: required(subject)
        ? subject.trim()
        : "SMTP Test Email",
      text: message
    });

    return {
      httpStatus: 200,
      body: {
        success: true,
        stage: "email_sent",
        message:
          "SMTP credentials are valid and the test email was sent successfully.",
        messageId: info.messageId,
        response: info.response,
        accepted: info.accepted,
        rejected: info.rejected,
        smtp
      }
    };
  } catch (error) {
    return {
      httpStatus: 500,
      body: {
        success: false,
        stage: "email_sending",
        error: error.message,
        code: error.code || null,
        command: error.command || null,
        response: error.response || null,
        responseCode: error.responseCode || null,
        smtp
      }
    };
  }
}

module.exports = { testSMTP };