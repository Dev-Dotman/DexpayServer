const functions = require("firebase-functions");
const express = require("express");
const { Sequelize, DataTypes } = require("sequelize");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const randomatic = require("randomatic");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const router = express.Router();
const axios = require("axios");
const { v4: uuidv4 } = require("uuid");
require("dotenv").config();
const { Op } = require("sequelize");

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USERNAME,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    dialect: "mysql",
  }
);

const jwt_key = process.env.JWT_KEY;

const app = express();
const port = 3003;
app.use(cors({ origin: true }));
app.use(bodyParser.json());

// Ensure uploads directory exists
if (!fs.existsSync("./uploads")) {
  fs.mkdirSync("./uploads");
}

if (!fs.existsSync("./uploads2")) {
  fs.mkdirSync("./uploads2");
}

// Set storage engine
const storage = multer.diskStorage({
  destination: "./uploads/", // path to save uploaded images
  filename: function (req, file, cb) {
    cb(
      null,
      file.fieldname + "-" + Date.now() + path.extname(file.originalname)
    );
  },
});

const storage2 = multer.diskStorage({
  destination: "./uploads/eventCover", // path to save uploaded images
  filename: function (req, file, cb) {
    cb(
      null,
      file.fieldname + "-" + Date.now() + path.extname(file.originalname)
    );
  },
});

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_KEY,
  },
});

async function sendEmail(to, text) {
  const mailOptions = {
    from: "your-email@gmail.com",
    to,
    subject: "Haztech SOS MESSAGE",
    html: text,
  };

  return transporter.sendMail(mailOptions);
}

// Function to generate a 10-character alphanumeric ID
const generateUniqueId = () => {
  return uuidv4().replace(/-/g, "").substr(0, 10);
};

const generateUserId = () => {
  return uuidv4().replace(/-/g, "").substr(0, 6);
};

// Init upload
const upload = multer({
  storage: storage,
  limits: { fileSize: 1000000 }, // limit file size to 1MB
  fileFilter: function (req, file, cb) {
    checkFileType(file, cb);
  },
}).single("profilePic"); // Ensure field name matches

const upload2 = multer({
  storage: storage2,
  limits: { fileSize: 1000000 }, // limit file size to 1MB
  fileFilter: function (req, file, cb) {
    checkFileType(file, cb);
  },
}).single("coverPhoto"); // Ensure field name matches

// Check file type
function checkFileType(file, cb) {
  // Allowed ext
  const filetypes = /jpeg|jpg|png|gif/;
  // Check ext
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  // Check mime
  const mimetype = filetypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb("Error: Images Only!");
  }
}

function generateEmailContent(recipientName, message) {
  return `
  <!DOCTYPE html>
  <html>
  <head>
      <title>WhatFlow Notification</title>
      <style>
          body {
              font-family: Arial, sans-serif;
              margin: 0;
              padding: 0;
              background-color: #ffffff;
          }
          .container {
              width: 100%;
              max-width: 600px;
              margin: 0 auto;
              padding: 20px;
              background-color: #ffffff;
              border: 1px solid #ddd;
          }
          .header {
              background-color: #128c7e;
              padding: 10px;
              text-align: center;
              color: #ffffff;
          }
          .content {
              padding: 20px;
              color: #333333;
          }
          .footer {
              background-color: #128c7e;
              padding: 10px;
              text-align: center;
              color: #ffffff;
          }
          .button {
              background-color: #128c7e;
              color: #ffffff;
              padding: 10px 20px;
              text-decoration: none;
              display: inline-block;
              margin: 10px 0;
              border-radius: 5px;
          }
      </style>
  </head>
  <body>
      <div class="container">
          <div class="header">
              <h1>WhatFlow</h1>
          </div>
          <div class="content">
              <h2>Hello, ${recipientName}!</h2>
              <p>${message}</p>
              <a href="#" class="button">Learn More</a>
          </div>
          <div class="footer">
              <p>&copy; 2024 WhatFlow. All rights reserved.</p>
          </div>
      </div>
  </body>
  </html>
  `;
}

const User = sequelize.define("User", {
  id: {
    type: DataTypes.STRING(6),
    primaryKey: true,
    allowNull: false,
    unique: true,
    validate: {
      isAlphanumeric: true,
      len: [6, 6],
    },
  },
  firstName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true,
    },
  },
  nickname: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  contact: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  imagePath: {
    type: DataTypes.STRING,
    allowNull: true, // Allow null because not all users may have an image
  },
});

const BankDetail = sequelize.define("BankDetail", {
  bankName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  bankCode: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  bankAccountNo: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  bankAccountName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  userEmail: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

User.hasMany(BankDetail, { foreignKey: "userEmail", sourceKey: "email" });
BankDetail.belongsTo(User, { foreignKey: "userEmail", targetKey: "email" });

const Revenue = sequelize.define("Revenue", {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    references: {
      model: User,
      key: "email",
    },
  },
  totalRevenue: {
    type: DataTypes.FLOAT,
    allowNull: false,
    defaultValue: 0,
  },
  revenueLast24h: {
    type: DataTypes.FLOAT,
    allowNull: false,
    defaultValue: 0,
  },
  revenueLast7d: {
    type: DataTypes.FLOAT,
    allowNull: false,
    defaultValue: 0,
  },
  revenueLast30d: {
    type: DataTypes.FLOAT,
    allowNull: false,
    defaultValue: 0,
  },
  revenueLast365d: {
    type: DataTypes.FLOAT,
    allowNull: false,
    defaultValue: 0,
  },
});

User.hasMany(Revenue, {
  foreignKey: "email",
});

Revenue.belongsTo(User, {
  foreignKey: "email",
});

const Transaction = sequelize.define("Transaction", {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    references: {
      model: "Users", // Ensure this matches the name of your User model's table
      key: "email",
    },
    onUpdate: "CASCADE",
    onDelete: "CASCADE",
  },
  courseName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  courseId: {
    type: DataTypes.STRING(10),
    primaryKey: false,
    allowNull: false,
  },
  amount: {
    type: DataTypes.FLOAT,
    allowNull: false,
  },
  date: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW,
  },
});

const Notification = sequelize.define(
  "Notification",
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    userEmail: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    title: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    message: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
    read: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
  },
  {
    timestamps: true,
  }
);

const Verification = sequelize.define("Verification", {
  userId: {
    type: DataTypes.STRING(6),
    primaryKey: true,
    allowNull: false,
    unique: true,
    validate: {
      isAlphanumeric: true,
      len: [6, 6],
    },
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true,
    },
  },
  isEmailVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
  phoneNo: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      isNumeric: true,
    },
  },
  isPhoneNoVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
});

User.hasMany(Transaction, { foreignKey: "email" });
Transaction.belongsTo(User, { foreignKey: "email" });

const Event = sequelize.define("Event", {
  id: {
    type: DataTypes.STRING(10),
    primaryKey: true,
    allowNull: false,
  },
  creator: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  creatorEmail: {
    type: DataTypes.STRING,
    allowNull: false,
    references: {
      model: "Users",
      key: "email",
    },
  },
  courseTitle: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  eventDate: {
    type: DataTypes.DATE,
    allowNull: false,
  },
  whatsappLink: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  courseDescription: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  courseCategory: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  courseDuration: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  endDate: {
    type: DataTypes.DATE,
    allowNull: false,
  },
  classSchedule: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  prerequisites: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  coverPhoto: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  courseFee: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  maxEnrolment: {
    type: DataTypes.INTEGER,
    allowNull: false,
  },
  joiningDeadline: {
    type: DataTypes.DATE,
    allowNull: false,
  },
  extraNotes: {
    type: DataTypes.TEXT,
    allowNull: true,
  },
  bankName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  bankCode: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  bankAccountNo: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  bankAccountName: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

// User Signup Route
app.post("/signup", upload, async (req, res) => {
    const { firstName, lastName, email, nickname, phoneNumber, password } = req.body;
  
    try {
      // Check if user already exists by email
      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        console.error("User with this email already exists:", email);
        return res.status(400).json({ error: "User with this email already exists." });
      }
  
      // Check if user already exists by phone number
      const existingNumber = await User.findOne({ where: { contact: phoneNumber } });
      if (existingNumber) {
        console.error("This phone number has been used before:", phoneNumber);
        return res.status(400).json({ error: "This phone number has been used before." });
      }
  
      // Check if user already exists by nickname
      const existingNickname = await User.findOne({ where: { nickname } });
      if (existingNickname) {
        console.error("This nickname has been used before:", nickname);
        return res.status(400).json({ error: "Sorry, that nickname has already been used. Please try something else." });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
      const userId = generateUserId();
  
      // Create new user
      const newUser = await User.create({
        id: userId,
        firstName,
        lastName,
        email,
        nickname,
        contact: phoneNumber,
        password: hashedPassword,
        imagePath: req.file ? `/uploads/${req.file.filename}` : null,
      });
  
      // Insert into verification table
      const newVerification = await Verification.create({
        userId: newUser.id,
        email,
        isEmailVerified: false,
        phoneNo: phoneNumber,
        isPhoneNoVerified: false,
      });
  
      // Create revenue entry
      await Revenue.create({
        email,
        totalRevenue: 0,
        revenueLast24h: 0,
        revenueLast7d: 0,
        revenueLast30d: 0,
        revenueLast365d: 0,
      });
  
      // Create a welcome notification
      const now = new Date();
      const message = `Hello ${nickname}, Welcome to WhatFlow. You created an account on ${now.toLocaleDateString()} at ${now.toLocaleTimeString()}.`;
      const title = `Account Creation`;
  
      await Notification.create({
        userEmail: email,
        title,
        message,
      });
  
      // Send welcome email
      const emailContent = generateEmailContent(nickname, message);
      await sendEmail(email, emailContent);
  
      res.status(201).json({ message: "User created successfully!", newUser });
    } catch (error) {
      console.error("Error: ", error);
      res.status(500).json({ error: "Internal server error. Please try again later." });
    }
  });
  

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ where: { email } });
    const bankDetails = await BankDetail.findOne({
      where: { userEmail: email },
    });

    if (!user) {
      return res.status(404).json({
        error: "User not found. \n Are you sure you have an account?",
      });
    }

    if (!bankDetails) {
    }

    // Check if the password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate a JWT token
    const token = jwt.sign({ id: user.id }, jwt_key, { expiresIn: "1h" });

    // Return user details along with the token
    res.status(200).json({
      message: "Login successful",
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        nickname: user.nickname,
        contact: user.contact,
        imagePath: user.imagePath,
        BankAccountNo: bankDetails?.bankAccountNo || "None",
        BankAccountName: bankDetails?.bankAccountName || "None",
        BankName: bankDetails?.bankName || "None",
        BankCode: bankDetails?.bankCode || "None",
      },
      token,
    });

    const now = new Date();

    const message = `Welcome back ${user.nickname}`;
    const title = `Account Sign In`;
    const message2 = `Account login for ${user.firstName} ${
      user.lastName
    } on ${now.toLocaleDateString()} ${now.toLocaleTimeString()} `;
    await Notification.create({
      userEmail: email,
      title,
      message,
    });

    const emailContent = generateEmailContent(user.nickname, message2);
    await sendEmail(email, emailContent);
  } catch (error) {
    res.status(500).json({ error: "Database error: " + error });
    console.error("error: ", error);
  }
});

app.get("/banks", async (req, res) => {
  try {
    const response = await axios.get("https://api.paystack.co/bank", {
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACKKEY1}`,
      },
    });
    res.json({ banks: response.data.data });
  } catch (error) {
    res.status(500).send("Error fetching banks");
    console.error("error fetching banks :", error);
  }
});

// Serve static files from the "uploads" directory
app.use("/uploads", express.static("uploads"));
app.use("/uploads/eventCover", express.static("uploads/eventCover"));

const verifyBankAccount = async (bankCode, accountNumber) => {
  const response = await axios.get(
    `https://api.paystack.co/bank/resolve?account_number=${accountNumber}&bank_code=${bankCode}`,
    {
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACKKEY1}`,
      },
    }
  );
  return response.data;
};

app.post("/verify-bank-account", async (req, res) => {
  const { bankCode, accountNumber } = req.body;
  const accountInfo = await verifyBankAccount(bankCode, accountNumber);
  res.json(accountInfo);
  console.log(accountInfo);
});

app.post("/storePaymentDetails", async (req, res) => {
  const { bankName, bankCode, bankAccountNo, bankAccountName, userEmail } =
    req.body;

  try {
    // Check if the user exists
    const user = await User.findOne({ where: { email: userEmail } });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if bank details for the user already exist
    const bankDetail = await BankDetail.findOne({ where: { userEmail } });

    if (bankDetail) {
      // Update existing bank details
      await bankDetail.update({
        bankName,
        bankCode,
        bankAccountNo,
        bankAccountName,
      });
      res
        .status(200)
        .json({ message: "Bank details updated successfully", bankDetail });

      const message = `You have successfully updated your payment information`;
      const title = `Payment Information Update`;
      const message2 = `payment info update ${bankAccountName} ${bankAccountNo} ${bankName}`;

      await Notification.create({
        userEmail,
        title,
        message,
      });

      const emailContent = generateEmailContent(userEmail, message2);
      await sendEmail(userEmail, emailContent);
    } else {
      // Create new bank details
      const newBankDetail = await BankDetail.create({
        bankName,
        bankCode,
        bankAccountNo,
        bankAccountName,
        userEmail,
      });
      res
        .status(201)
        .json({ message: "Bank details created successfully", newBankDetail });
    }

    const message = `Congratulations! You have successfully added your payment information`;
    const title = `Payment Information Update`;

    await Notification.create({
      userEmail,
      title,
      message,
    });

    const message2 = `payment info added ${bankAccountName} ${bankAccountNo} ${bankName}`;
    const emailContent = generateEmailContent(userEmail, message2);
    await sendEmail(userEmail, emailContent);
  } catch (error) {
    res.status(400).json({ error: error.message });
    console.error("Error storing bank details:", error);
  }
});

app.post("/events", upload2, async (req, res) => {
  const {
    creator,
    creatorEmail,
    courseTitle,
    eventDate,
    whatsappLink,
    courseDescription,
    courseCategory,
    courseDuration,
    endDate,
    classSchedule,
    prerequisites,
    coverPhoto,
    courseFee,
    maxEnrolment,
    joiningDeadline,
    extraNotes,
    bankName,
    bankCode,
    bankAccountNo,
    bankAccountName,
  } = req.body;

  try {
    // Check if the user exists
    const user = await User.findOne({ where: { email: creatorEmail } });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const eventId = generateUniqueId();
    const coverPhotoPath = req.file
      ? `/uploads/eventCover/${req.file.filename}`
      : null;

    // Create the event
    const event = await Event.create({
      id: eventId,
      creator,
      creatorEmail,
      courseTitle,
      eventDate,
      whatsappLink,
      courseDescription,
      courseCategory,
      courseDuration,
      endDate,
      classSchedule,
      prerequisites,
      coverPhoto: req.file ? `/uploads/eventCover/${req.file.filename}` : null,
      courseFee,
      maxEnrolment,
      joiningDeadline,
      extraNotes,
      bankName,
      bankCode,
      bankAccountNo,
      bankAccountName,
    });

    res.status(201).json(event);

    const message = `You have successfully listed a course on Whatflow`;
    const title = `Event notification`;

    await Notification.create({
      userEmail: creatorEmail,
      title,
      message,
    });

    const message2 = `Your course '${courseTitle}' with the id ${eventId} has been successfully listed on WhatFlow`;
    const emailContent = generateEmailContent(creatorEmail, message2);
    await sendEmail(creatorEmail, emailContent);
  } catch (error) {
    res.status(400).json({ error: error.message });
    console.error("Error creating event:", error);
  }
});

app.get("/myevents", async (req, res) => {
  const userEmail = req.query.email;

  if (!userEmail) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    const events = await Event.findAll({ where: { creatorEmail: userEmail } });
    res.json({ events });
  } catch (error) {
    console.error("Error fetching events:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

const calculateRevenue = async (userEmail) => {
  try {
    const transactions = await Transaction.findAll({
      where: { email: userEmail },
    });

    const now = new Date();
    const totalRevenue = transactions.reduce(
      (acc, transaction) => acc + transaction.amount,
      0
    );
    const revenueLast24h = transactions
      .filter((t) => now - new Date(t.date) <= 24 * 60 * 60 * 1000)
      .reduce((acc, transaction) => acc + transaction.amount, 0);
    const revenueLast7d = transactions
      .filter((t) => now - new Date(t.date) <= 7 * 24 * 60 * 60 * 1000)
      .reduce((acc, transaction) => acc + transaction.amount, 0);
    const revenueLast30d = transactions
      .filter((t) => now - new Date(t.date) <= 30 * 24 * 60 * 60 * 1000)
      .reduce((acc, transaction) => acc + transaction.amount, 0);
    const revenueLast365d = transactions
      .filter((t) => now - new Date(t.date) <= 365 * 24 * 60 * 60 * 1000)
      .reduce((acc, transaction) => acc + transaction.amount, 0);

    await Revenue.upsert({
      email: userEmail,
      totalRevenue,
      revenueLast24h,
      revenueLast7d,
      revenueLast30d,
      revenueLast365d,
    });
  } catch (error) {
    console.error("Error calculating revenue:", error);
  }
};

app.get("/user/revenue", async (req, res) => {
  const { email } = req.query;
  calculateRevenue(email);
  const revenue = await Revenue.findOne({
    where: {
      email: email,
    },
    order: [["createdAt", "DESC"]],
  });

  if (revenue) {
    // Delete all entries except the most recent one
    await Revenue.destroy({
      where: {
        email,
        id: { [Op.ne]: revenue.id }, // [Op.ne] means "not equal"
      },
    });
  }

  const transactions = await Transaction.findAll({
    where: {
      email: email,
    },
    order: [["date", "DESC"]],
  });

  res.json({
    revenue: revenue, // Assuming there's an 'amount' field in the Revenue model
    transactions: transactions,
  });
});

app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  // Generate OTP
  const otp = generateUserId();

  try {
    // Send email with nodemailer

    const message = `Your Email verification OTP is ${otp} `;

    const emailContent = generateEmailContent(email, message);

    await sendEmail(email, emailContent);

    // You can optionally save the OTP in your database for verification purposes

    const message2 = `An OTP was sent to your email`;
    const title = `WhatFlow OTP Update`;

    await Notification.create({
      userEmail: email,
      title,
      message: message2,
    });
    res.status(200).json({ message: "OTP sent successfully.", otp: otp });
  } catch (error) {
    console.error("Error sending OTP:", error);
    res
      .status(500)
      .json({ error: "Failed to send OTP. Please try again later." });
  }
});

// Endpoint to update email verification status
app.put("/verify/email/:email", async (req, res) => {
  const email = req.params.email;
  console.log(email);
  try {
    const user = await User.findOne({
      where: {
        email: email,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    // Update user's email verification status to true
    await Verification.update(
      { isEmailVerified: true },
      { where: { email: email } }
    );

    res.status(200).json({ message: "Email verification status updated." });

    const message = `Congratulations! Your Email has been verified`;
    const title = `WhatFlow Verification Update`;

    await Notification.create({
      userEmail: email,
      title,
      message,
    });

    const emailContent = generateEmailContent(email, message);
    await sendEmail(email, emailContent);
  } catch (error) {
    res.status(500).json({ error: "Database error: " + error });
    console.error("Error: ", error);
  }
});

app.get("/verification/:email", async (req, res) => {
  const email = req.params.email;

  try {
    const verificationData = await Verification.findOne({
      where: { email },
    });

    if (!verificationData) {
      return res.status(404).json({ error: "Verification data not found." });
    }

    res.status(200).json(verificationData);
  } catch (error) {
    res.status(500).json({ error: "Database error: " + error });
    console.error("Error: ", error);
  }
});

// Endpoint to update phone number verification status
app.put("/verify/phone/:email", async (req, res) => {
  const email = req.params.userId;

  try {
    const user = await User.findByPk(email);

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    // Update user's phone number verification status to true
    await Verification.update(
      { isPhoneNoVerified: true },
      { where: { email: email } }
    );

    res
      .status(200)
      .json({ message: "Phone number verification status updated." });
  } catch (error) {
    res.status(500).json({ error: "Database error: " + error });
    console.error("Error: ", error);
  }
});

app.post("/change-password", async (req, res) => {
  const { email, oldPassword, newPassword } = req.body;
  console.log(oldPassword);

  if (!email || !oldPassword || !newPassword) {
    return res
      .status(400)
      .json({ error: "Email, old password, and new password are required." });
  }

  try {
    // Find the user by email
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    // Check if the old password is correct
    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Incorrect old password." });
    }

    // Hash the new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password
    await user.update({ password: hashedNewPassword });

    res.status(200).json({ message: "Password changed successfully." });

    const message = `You have successfully changed your password`;
    const title = `WhatFlow Account Update`;

    await Notification.create({
      userEmail,
      title,
      message,
    });

    const message2 = `The password on your account was changed`;
    const emailContent = generateEmailContent(email, message2);
    await sendEmail(email, emailContent);
  } catch (error) {
    console.error("Error changing password:", error);
    res.status(500).json({ error: "Database error: " + error.message });
  }
});

app.put("/update-email", async (req, res) => {
  const { oldEmail, newEmail } = req.body;

  try {
    // Begin a transaction
    await sequelize.transaction(async (t) => {
      // Update User table
      await User.update(
        { email: newEmail },
        { where: { email: oldEmail }, transaction: t }
      );

      // Update BankDetail table
      await BankDetail.update(
        { userEmail: newEmail },
        { where: { userEmail: oldEmail }, transaction: t }
      );

      // Update Revenue table
      await Revenue.update(
        { email: newEmail },
        { where: { email: oldEmail }, transaction: t }
      );

      // Update Transaction table
      await Transaction.update(
        { email: newEmail },
        { where: { email: oldEmail }, transaction: t }
      );

      // Update Verification table
      await Verification.update(
        { email: newEmail },
        { where: { email: oldEmail }, transaction: t }
      );

      // Update Event table
      await Event.update(
        { creatorEmail: newEmail },
        { where: { creatorEmail: oldEmail }, transaction: t }
      );

      // Update user's email verification status to false (if needed)
      await Verification.update(
        { isEmailVerified: false },
        { where: { email: newEmail }, transaction: t }
      );

      // No need to commit here, as Sequelize handles commit automatically if there's no error
    });

    res.status(200).json({
      message: `Email successfully changed from ${oldEmail} to ${newEmail}.`,
    });

    const message = `You have successfully updated your email`;
    const title = `WhatFlow Account Update`;

    await Notification.create({
      userEmail: newEmail,
      title,
      message,
    });

    const message2 = `Your email has been successfully changed to ${newEmail}`;
    const emailContent = generateEmailContent(oldEmail, message2);
    await sendEmail(oldEmail, emailContent);
  } catch (error) {
    console.error("Error updating email in all tables:", error);
    res.status(500).json({ error: "Error updating email in all tables." });
  }
});

app.delete("/delete-account", async (req, res) => {
  const { email } = req.body;

  try {
    // Begin a transaction
    await sequelize.transaction(async (t) => {
      // Delete from User table
      await User.destroy({ where: { email }, transaction: t });

      // Delete from BankDetail table
      await BankDetail.destroy({ where: { userEmail: email }, transaction: t });

      // Delete from Revenue table
      await Revenue.destroy({ where: { email }, transaction: t });

      // Delete from Transaction table
      await Transaction.destroy({ where: { email }, transaction: t });

      // Delete from Verification table
      await Verification.destroy({ where: { email }, transaction: t });

      // Delete from Event table
      await Event.destroy({ where: { creatorEmail: email }, transaction: t });

      // No need to commit here, Sequelize handles commit automatically if there's no error
    });

    res.status(200).json({
      message: `Account with email ${email} deleted successfully from all tables.`,
    });
  } catch (error) {
    console.error("Error deleting account:", error);
    res.status(500).json({ error: "Error deleting account." });
  }
});

app.get("/notifications", async (req, res) => {
  const { email } = req.query;

  try {
    const notifications = await Notification.findAll({
      where: { userEmail: email, read: 0 },
      order: [["createdAt", "DESC"]],
    });
    res.status(200).json({ notifications });
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({ error: "Error fetching notifications" });
  }
});

app.put("/notifications/read", async (req, res) => {
  const { ids } = req.body;

  try {
    await Notification.update({ read: 1 }, { where: { id: ids } });
    res.status(200).json({ message: "Notifications marked as read" });
  } catch (error) {
    console.error("Error marking notifications as read:", error);
    res.status(500).json({ error: "Error marking notifications as read" });
  }
});

sequelize.sync().catch((err) => {
  console.error("Unable to connect to the database:", err);
});

exports.api = functions.https.onRequest(app);
