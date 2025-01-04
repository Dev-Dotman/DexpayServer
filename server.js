const express = require("express");
const session = require("express-session");
const { Sequelize, DataTypes } = require("sequelize");
const bcrypt = require("bcryptjs");
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
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
require("dotenv").config();
const { Op } = require("sequelize");
const bs58 = require("bs58");
const nacl = require("tweetnacl");
const WebSocket = require("ws");
const puppeteer = require("puppeteer");
const {
  Connection,
  PublicKey,
  Keypair,
  SystemProgram,
  sendAndConfirmTransaction,
  TransactionInstruction,
  clusterApiUrl,
  GetVersionedTransactionConfig,
  SYSVAR_RENT_PUBKEY,
  LAMPORTS_PER_SOL,
  Transaction,
} = require("@solana/web3.js");
const {
  Token,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
} = require("@solana/spl-token");

const anchor = require("@project-serum/anchor");

const {
  sequelize,
  User,
  PaymentRequest,
  Transaction2,
  CryptoPrice,
  Log,
  Notification,
  PaymentLinks,
  simpleUser,
  Refund,
  txSessionStore
} = require("./Models");

const jwt_key = process.env.JWT_KEY;

const TOKEN_EXPIRY = process.env.TOKEN_EXPIRY;

const app = express();
const port = process.env.PORT || 3000;
app.use(
  cors({
    // origin: function (origin, callback) {
    //   // List of allowed origins
    //   const allowedOrigins = [
    //     "http://192.168.173.81:3000",
    //     "http://192.168.173.81:3001",
    //   ];
    //   if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
    //     callback(null, true); // Allow the request
    //   } else {
    //     callback(new Error("Not allowed by CORS")); // Reject the request
    //   }
    // },
    origin: true,
    methods: "GET,POST,PUT,DELETE,OPTIONS",
    allowedHeaders: "Content-Type,Authorization",
    credentials: true, // Allow cookies to be sent
  })
);

// Configure session middleware
app.use(
  session({
    store: txSessionStore,
    secret: process.env.JWT_KEY || "yourSecretKey",
    resave: false, // Avoid saving unchanged sessions
    saveUninitialized: false, // Don't save uninitialized sessions
    cookie: {
      maxAge: 30 * 60 * 1000, // 30 days
      secure: true, // Set to true if you're using HTTPS
      httpOnly: true, // Prevents client-side script access
    },
  })
);

txSessionStore.sync({ alter: true });

// app.use(
//   session({
//     secret: process.env.JWT_KEY, // You should use a strong secret key
//     resave: false, // Do not resave session if not modified
//     saveUninitialized: true, // Save a new session even if it's not initialized
//     cookie: {
//       maxAge: 30 * 60 * 1000, // Cookie will expire after 30 minutes
//       secure: false, // Set to true if using HTTPS
//       sameSite: "lax",
//     },
//   })
// );

// Transaction middleware
const transactionMiddleware = (req, res, next) => {
  // Save the Keypair in the session
  req.saveTransactionKeypair = (keypair) => {
    req.session.tx = {
      publicKey: Array.from(keypair._keypair.publicKey),
      secretKey: Array.from(keypair._keypair.secretKey),
    };
    req.session.save((err) => {
      if (err) {
        console.error('Failed to save session:', err);
      } else {
        console.log('Keypair saved in session.');
      }
    });
  };

  // Retrieve the Keypair by fetching the session from the database
  req.getTransactionKeypair = async () => {
    const sessionId = req.sessionID; // Current session ID
    try {
      // Query the session table to fetch session data
      const sessionData = await txSessionStore.sessionModel.findOne({
        where: { sid: sessionId },
      });

      if (sessionData && sessionData.data) {
        const sessionParsed = JSON.parse(sessionData.data);
        if (sessionParsed.tx) {
          const { publicKey, secretKey } = sessionParsed.tx;
          return new Keypair({
            publicKey: Uint8Array.from(publicKey),
            secretKey: Uint8Array.from(secretKey),
          });
        }
      }

      console.log('No Keypair found in session.');
      return null;
    } catch (error) {
      console.error('Error fetching session from database:', error);
      return null;
    }
  };

  next();
};

app.use(transactionMiddleware);

app.use(express.json());

const storage = multer.diskStorage({
  destination: "./uploads/", // path to save uploaded images
  filename: function (req, file, cb) {
    cb(
      null,
      file.fieldname + "-" + Date.now() + path.extname(file.originalname)
    );
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 4000000 }, // limit file size to 1MB
  fileFilter: function (req, file, cb) {
    checkFileType(file, cb);
  },
}).single("profilePic"); // Ensure field name matches

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.use(bodyParser.json());

const wss = new WebSocket.Server({ noServer: true });

wss.on("connection", (ws, req) => {
  // Parse token from query parameter
  const token = new URL(
    request.url,
    `https://${req.headers.host}`
  ).searchParams.get("token");

  if (!token) {
    ws.close();
    return;
  }

  // Verify JWT token
  jwt.verify(token, process.env.JWT_KEY, (err, decoded) => {
    if (err) {
      ws.close();
      return;
    }

    //console.log("Client connected:", decoded);

    ws.on("message", (message) => {
      //console.log(`Received message: ${message}`);
      ws.send(`Server received: ${message}`);
    });

    ws.on("close", () => {
      //console.log("Client disconnected");
    });

    ws.on("error", (error) => {
      //console.log("WebSocket error:", error);
    });
  });
});

//console.log("WebSocket server is running");

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.post("/get-image", (req, res) => {
  const { imagePath } = req.body; // Get the image path from the request body
  const imageFullPath = path.join(__dirname, imagePath); // Construct the full path to the image

  res.sendFile(imageFullPath, (err) => {
    if (err) {
      console.error("Failed to send image:", err);
    }
  });
});

app.post("/get-image2", (req, res) => {
  const { imagePath } = req.body; // Get the image path from the request body
  const imageFullPath = path.join(__dirname, imagePath); // Construct the full path to the image

  res.sendFile(imageFullPath, (err) => {
    if (err) {
      console.error("Failed to send image:", err);
    }
  });
});

// Ensure uploads directory exists
if (!fs.existsSync("./uploads")) {
  fs.mkdirSync("./uploads");
}

if (!fs.existsSync("./uploads2")) {
  fs.mkdirSync("./uploads2");
}

// Set storage engine

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
    from: "theoutsourcestudio01@gmail.com",
    to,
    subject: "Dexpay Message",
    html: text,
  };

  return transporter.sendMail(mailOptions);
}

async function sendReceipt(to, text, buffer) {
  const mailOptions = {
    from: "theoutsourcestudio01@gmail.com",
    to,
    subject: "Dexpay Message",
    html: text,
    attachments: [
      {
        filename: "receipt.pdf",
        content: buffer, // Attach the generated PDF as a buffer
        contentType: "application/pdf",
      },
    ],
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
      <title>Dexpay Notification</title>
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
              background-color: #1e1e2e;
              padding: 10px;
              text-align: center;
              color: #ffffff;
          }
          .content {
              padding: 20px;
              color: #333333;
          }
          .footer {
              background-color: #1e1e2e;
              padding: 10px;
              text-align: center;
              color: #ffffff;
          }
          .button {
              background-color: #1e1e2e;
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
              <h1>Dexpay</h1>
          </div>
          <div class="content">
              <h2>Hello, ${recipientName}!</h2>
              <p>${message}</p>
              <a href="#" class="button">Learn More</a>
          </div>
          <div class="footer">
              <p>&copy; 2024 Dexpay. All rights reserved.</p>
          </div>
      </div>
  </body>
  </html>
  `;
}

// Merchant Signup Route
app.post("/signup", upload, async (req, res) => {
  const { firstName, lastName, email, nickname, phoneNumber, password } =
    req.body;

  try {
    // Check if user already exists by email
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      console.error("User with this email already exists:", email);
      return res.status(400).json({
        error: `Sorry ${firstName}, a user with this email already exists.`,
      });
    }

    // Check if user already exists by phone number
    const existingNumber = await User.findOne({
      where: { contact: phoneNumber },
    });
    if (existingNumber) {
      console.error(
        `Sorry ${firstName}, this phone number has been used before :(`,
        phoneNumber
      );
      return res.status(400).json({
        error: `Sorry ${firstName}, this phone number has been used before:`,
      });
    }

    // Check if user already exists by nickname
    const existingNickname = await User.findOne({ where: { nickname } });
    if (existingNickname) {
      console.error("This nickname has been used before:", nickname);
      return res.status(400).json({
        error: `Sorry ${firstName}, that nickname has already been used :( Please try something else.`,
      });
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
    // Create a welcome notification
    const now = new Date();
    const message = `Hello ${nickname}, Welcome to Dexpay. You created an account on ${now.toLocaleDateString()} at ${now.toLocaleTimeString()}.`;
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
    res
      .status(500)
      .json({ error: "Internal server error. Please try again later." });
  }
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

//simple user signup route
app.post("/register", async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      console.error("User with this email already exists:", email);
      return res.status(400).json({
        error: `Sorry ${firstName}, a user with this email already exists.`,
      });
    }

    const newUser = await simpleUser.create({
      firstName,
      lastName,
      email: email.toLowerCase(),
      password: hashedPassword,
    });

    res.status(201).json({
      message: "user registered successfully",
      success: true,
      user: newUser,
    });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//merchant login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(404).json({
        error: "User not found. \n Are you sure you have an account?",
      });
    }

    // Check if the password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate a JWT token with necessary user details
    const userToken = {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      nickname: user.nickname,
      contact: user.contact,
      imagePath: user.imagePath, // Profile photo
    };

    // Sign the JWT with the payload and expiration
    const accessToken = jwt.sign(userToken, process.env.JWT_KEY, {
      expiresIn: process.env.TOKEN_EXPIRY || "1h", // Adjust the token expiry as needed
    });

    // Respond with the access token
    res.json({ message: "Login successful", accessToken });

    // Send a notification and email for successful login
    const now = new Date();
    const message = `Welcome back ${user.nickname}`;
    const title = `Account Sign In`;
    const message2 = `Account login for ${user.firstName} ${
      user.lastName
    } on ${now.toLocaleDateString()} ${now.toLocaleTimeString()}`;

    await Log.create({
      user_id: user.id,
      event_type: "Login",
      message: message2,
    });

    const emailContent = generateEmailContent(user.nickname, message2);
    await sendEmail(email, emailContent);
  } catch (error) {
    res.status(500).json({ error: "Database error: " + error });
    console.error("Error: ", error);
  }
});

//simple user login
app.post("/loginSU", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find the user by email
    const mail = email.toLowerCase();
    const user = await simpleUser.findOne({ where: { email } });

    const users = await simpleUser.findAll(); // Fetch all records from the table
    console.log(
      "Table Data:",
      users.map((user) => user.toJSON())
    ); // Format and display results
    console.log(user);

    if (!user) {
      return res.status(404).json({
        error: "User not found. \n Are you sure you have an account?",
      });
    }

    // Check if the password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate a JWT token
    const userToken = {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
    }; // Payload to include in the token
    const accessToken = jwt.sign(userToken, process.env.JWT_KEY, {
      expiresIn: TOKEN_EXPIRY,
    });
    res.json({ message: "Login successful", accessToken });

    const now = new Date();

    const message = `Welcome back ${user.firstName}`;
    const title = `Account Sign In`;
    const message2 = `Account login for ${user.firstName} ${
      user.lastName
    } on ${now.toLocaleDateString()} ${now.toLocaleTimeString()} `;
    await Notification.create({
      userEmail: email,
      title,
      message,
    });

    const emailContent = generateEmailContent(user.firstName, message2);
    await sendEmail(email, emailContent);
  } catch (error) {
    res.status(500).json({ error: "Database error: " + error });
    console.error("error: ", error);
  }
});

app.get("/api/protected-endpoint", authenticateToken, (req, res) => {
  res.json({ message: "protected endpoint", user: req.user });
});

app.post("/banks", async (req, res) => {
  const { email } = req.body;
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
  try {
    const response = await axios.get(
      `https://api.paystack.co/bank/resolve?account_number=${accountNumber}&bank_code=${bankCode}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACKKEY1}`,
        },
      }
    );
    return response.data;
  } catch (error) {
    if (error.response && error.response.data) {
      throw new Error(error.response.data.message);
    }
    throw new Error("An error occurred while verifying the bank account");
  }
};

app.post("/verify-bank-account", async (req, res) => {
  try {
    const { bankCode, accountNumber } = req.body;
    const accountInfo = await verifyBankAccount(bankCode, accountNumber);
    res.json(accountInfo);
  } catch (err) {
    let errorMessage = "An error occurred while verifying the bank account";

    if (err.message.includes("Invalid bank code")) {
      errorMessage = "Invalid bank code";
    } else if (err.message.includes("Invalid account number")) {
      errorMessage = "Invalid account number";
    }

    res.status(400).json({ error: errorMessage });
    console.error(err.message);
  }
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

const crypto = require("crypto");

// Load wallet from JSON file
const walletJsonFilePath = process.env.ANCHOR_WALLET; // Update with your file path
const walletData = JSON.parse(fs.readFileSync(walletJsonFilePath, "utf8"));
const secretKey2 = new Uint8Array(walletData);
const keypair2 = Keypair.fromSecretKey(secretKey2);

// async function initializeMerchantAccount(authority) {
//   // Create a new merchant account
//   const merchantAccount = anchor.web3.Keypair.generate();

//   try {
//     const idl = await anchor.Program.fetchIdl(programId, provider);
//     const program = new anchor.Program(idl, programId, provider);
//     // Call the initialize_merchant_account function
//     await program.methods
//       .initializeMerchantAccount(authority)
//       .accounts({
//         merchantAccount: merchantAccount.publicKey,
//         user: provider.wallet.publicKey,
//         systemProgram: anchor.web3.SystemProgram.programId,
//       })
//       .signers([keypair2, merchantAccount]) // Include the new merchant account as a signer
//       .rpc();

//     const merchantAccountInfo = await program.account.merchantAccount.fetch(
//       merchantAccount.publicKey
//     );

//     //console.log("merchant account initialized:", merchantAccountInfo);

//     return {
//       success: true,
//       message: "Merchant account initialized successfully",
//       merchantAccount: merchantAccount.publicKey.toString(),
//       auth: merchantAccount,
//     };
//   } catch (error) {
//     console.error("Error initializing merchant account:", error);
//     return {
//       success: false,
//       message: `Error initializing merchant account: ${error.message}`,
//     };
//   }
// }

app.post("/createPayment", async (req, res) => {
  const {
    amount_fiat,
    amount_crypto,
    currency,
    wallet_address,
    description,
    link_name,
    merchant_id,
    merchant_email,
    status,
  } = req.body;

  try {
    // Create a unique 25-character hash
    const hashInput = `${merchant_id}-${link_name}-${new Date().getTime()}`;
    const key = crypto
      .createHash("sha256")
      .update(hashInput)
      .digest("hex")
      .substring(0, 25);

    const authority = new anchor.web3.PublicKey(wallet_address);

    const initializedMerchant = authority;

    if (initializedMerchant.success === false) {
      return res.status(401).json({
        message: initializedMerchant.message,
      });
    }
    console.log(initializedMerchant);
    // Create the new payment link with the generated key
    const newPaymentLink = await PaymentLinks.create({
      amount_fiat,
      amount_crypto,
      currency,
      wallet_address,
      description,
      link_name,
      merchant_id,
      merchant_email,
      status,
      key, // Store the generated key in the 'key' field
      initializedWalletAddress: wallet_address,
    });

    return res.status(201).json({
      message: "Payment link created successfully",
      paymentLink: newPaymentLink,
    });
  } catch (error) {
    console.error("Error creating payment link:", error);
    return res.status(500).json({
      message: "Failed to create payment link",
      error: error.message,
    });
  }
});

app.post("/payment-links", async (req, res) => {
  const { merchant_id } = req.body;

  if (!merchant_id) {
    return res.status(400).json({ message: "Merchant ID is required." });
  }

  try {
    const paymentLinks = await PaymentLinks.findAll({
      where: { merchant_id },
    });

    res.status(200).json(paymentLinks);
  } catch (error) {
    console.error("Error fetching payment links:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post("/fetchTransactions2", async (req, res) => {
  const { payment_link_ids } = req.body; // List of payment link IDs sent from frontend

  try {
    // Step 1: Fetch the latest 5 transactions that match the payment_link_ids
    const transactions = await Transaction2.findAll({
      where: {
        payment_request_id: payment_link_ids, // Match payment_link_ids to payment_request_id
      },
      order: [["created_at", "DESC"]], // Order by latest transactions
      limit: 5, // Limit to 5 transactions
    });

    // Extract unique payment_request_ids from the transactions
    const paymentRequestIds = transactions.map((t) => t.payment_request_id);

    // Step 2: Fetch associated payment link names using the payment_request_ids
    const paymentLinks = await PaymentLinks.findAll({
      where: {
        key: paymentRequestIds, // Match key to payment_request_id
      },
      attributes: ["key", "link_name"], // Fetch the key and name
    });

    // Create a map for quick lookup of payment link names by key
    const paymentLinkMap = {};
    paymentLinks.forEach((link) => {
      paymentLinkMap[link.key] = link.link_name;
    });

    // Step 3: Restructure the transactions data to include the payment link name
    const transactionData = transactions.map((transaction) => ({
      id: transaction.id,
      amount: transaction.amount_merchant,
      transaction_hash: transaction.transaction_hash,
      payer_email: transaction.payer_email,
      payment_link_name:
        paymentLinkMap[transaction.payment_request_id] || "Unknown", // Get name from the map
      created_at: transaction.created_at,
    }));

    // Step 4: Calculate total revenue (sum of total_amount for all matching transactions)
    const totalRevenue = await Transaction2.sum("amount_merchant", {
      where: {
        payment_request_id: payment_link_ids,
      },
    });

    // Calculate revenue based on time periods: 24h, 7d, 30d, 365d
    const currentTime = new Date();
    const timePeriods = {
      "24h": new Date(currentTime.setDate(currentTime.getDate() - 1)),
      "7d": new Date(currentTime.setDate(currentTime.getDate() - 6)),
      "30d": new Date(currentTime.setDate(currentTime.getDate() - 23)),
      "365d": new Date(currentTime.setDate(currentTime.getDate() - 335)),
    };

    // Function to calculate revenue over specific time periods
    const revenueByPeriod = async (startTime) => {
      return await Transaction2.sum("amount_merchant", {
        where: {
          payment_request_id: payment_link_ids,
          created_at: {
            [Op.gte]: startTime, // Transactions within the specified time period
          },
        },
      });
    };

    const revenue24h = await revenueByPeriod(timePeriods["24h"]);
    const revenue7d = await revenueByPeriod(timePeriods["7d"]);
    const revenue30d = await revenueByPeriod(timePeriods["30d"]);
    const revenue365d = await revenueByPeriod(timePeriods["365d"]);

    // Structure revenue data for chart display
    const revenueData = {
      labels: ["24h", "7d", "30d", "365d"], // Time ranges for chart
      datasets: [
        {
          label: "Revenue",
          data: [
            revenue24h || 0,
            revenue7d || 0,
            revenue30d || 0,
            revenue365d || totalRevenue || 0, // Default to totalRevenue if no specific time revenue exists
          ],
          backgroundColor: "rgba(0, 123, 255, 0.5)",
          borderColor: "rgba(0, 123, 255, 1)",
          borderWidth: 2,
        },
      ],
    };

    // Send response with transactions and total revenue
    res.json({
      transactions: transactionData,
      totalRevenue, // Total of all transactions
      revenueData, // Structured data for chart display
      message: "Transactions fetched successfully",
    });
  } catch (error) {
    console.error("Error fetching transactions:", error);
    res.status(500).json({ message: "Failed to fetch transactions" });
  }
});

app.post("/fetchTransactions", async (req, res) => {
  const { payment_link_id, filter } = req.body; // Get filter from request

  if (!payment_link_id) {
    return res.status(400).json({ error: "Payment link ID is required." });
  }

  try {
    const paymentLink = await PaymentLinks.findOne({
      where: { key: payment_link_id },
    });

    if (!paymentLink) {
      return res.status(404).json({ error: "Payment link not found." });
    }

    let transactions;
    const now = new Date();
    const timeRanges = {
      "24h": new Date(now.getTime() - 24 * 60 * 60 * 1000),
      "7d": new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000),
      "30d": new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000),
      "365d": new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000),
    };

    if (filter && filter !== "all") {
      transactions = await Transaction2.findAll({
        where: {
          payment_request_id: payment_link_id,
          created_at: { [Op.gte]: timeRanges[filter] }, // Filter by the selected time range
        },
      });
    } else {
      transactions = await Transaction2.findAll({
        where: { payment_request_id: payment_link_id },
      });
    }

    const totalRevenue = transactions.reduce((total, transaction) => {
      return total + transaction.amount_merchant;
    }, 0);

    const merchantPublicKey = new PublicKey(
      paymentLink.initializedWalletAddress
    );
    const merchantBalanceLamports = await provider.connection.getBalance(
      merchantPublicKey
    );
    const merchantBalanceSOL = merchantBalanceLamports / LAMPORTS_PER_SOL;

    // Update labels based on the filter
    const labels = {
      "24h": ["Last 24 Hours"],
      "7d": ["Last 7 Days"],
      "30d": ["Last 30 Days"],
      "365d": ["Last 365 Days"],
      all: ["All Time"],
    };

    const revenueData = {
      labels: labels[filter || "all"], // Use filter to generate labels
      datasets: [
        {
          label: "Revenue",
          data: [totalRevenue], // Total revenue for the selected time range
          backgroundColor: "rgba(0, 123, 255, 0.5)",
          borderColor: "rgba(0, 123, 255, 1)",
          borderWidth: 2,
        },
      ],
    };

    res.json({
      transactions,
      totalRevenue,
      revenueData,
      paymentLink,
      balance: merchantBalanceSOL,
    });
  } catch (error) {
    console.error("Error fetching transactions:", error);
    res
      .status(500)
      .json({ error: "An error occurred while fetching transactions." });
  }
});

app.get("/payment/:token", async (req, res) => {
  const { token } = req.params;

  try {
    // Verify and decode the token

    // Fetch event details based on the eventId
    const pay = await PaymentLinks.findOne({ where: { key: token } });

    if (!pay) {
      return res.status(404).json({ message: "Payment Link not found" });
    }

    // Fetch guests and tickets for the event

    // Send event details, guests, and tickets to the frontend
    res.json({
      pay,
    });
  } catch (error) {
    console.error("Error fetching event details:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Load wallet keypair from the JSON file
const walletPath = process.env.ANCHOR_WALLET;
const walletKeypair = Keypair.fromSecretKey(
  new Uint8Array(JSON.parse(fs.readFileSync(walletPath)))
);

// Connect to Solana devnet
const connection = new Connection(
  clusterApiUrl(process.env.CLUSTER),
  "confirmed"
);
const provider = new anchor.AnchorProvider(
  connection,
  new anchor.Wallet(walletKeypair),
  {
    commitment: "confirmed",
    preflightCommitment: "processed",
  }
);
anchor.setProvider(provider);
// Load your escrow program
const programId = new anchor.web3.PublicKey(process.env.RUST_PROGRAM_ID); // Replace with your program ID

const createWalletAddress = () => {
  const keypair = Keypair.generate(); // Generate a new keypair for the wallet
  return keypair.publicKey.toString(); // Return the public key as the wallet address
};

const authority = process.env.PLATFORM_WALLET_SOL;

// const initializePlatformAccount = async (authority) => {
//   const idl = await anchor.Program.fetchIdl(programId, provider);
//   const program = new anchor.Program(idl, programId, provider);

//   // Generate a new public key for the platform account
//   const platformAccountKeypair = Keypair.generate();

//   try {
//     const response = await program.methods
//       .initializePlatformAccount(new anchor.web3.PublicKey(authority))
//       .accounts({
//         platformAccount: platformAccountKeypair.publicKey, // Use the public key from the generated keypair
//         user: provider.wallet.publicKey,
//         systemProgram: anchor.web3.SystemProgram.programId,
//       })
//       .signers([keypair2, platformAccountKeypair]) // Sign with the new keypair
//       .rpc();

//     const PlatformAccountInfo = await program.account.platformAccount.fetch(
//       platformAccountKeypair.publicKey
//     );

//     //console.log("Platform account initialized:", PlatformAccountInfo);

//     return platformAccountKeypair.publicKey.toString();
//   } catch (error) {
//     console.error("Error initializing platform account:", error);
//     return null;
//   }
// };

// Function to create a new system account
// async function createSystemAccount(signer) {
//   const newAccount = Keypair.generate(); // Generate a new system account keypair

//   // const idl = await anchor.Program.fetchIdl(programId, provider);
//   // const program = new anchor.Program(idl, programId, provider);
//   const secretKey = new Uint8Array(Object.values(signer._keypair.secretKey));
//   const keypair = Keypair.fromSecretKey(secretKey);
//   const lamportsRequired = await connection.getMinimumBalanceForRentExemption(
//     0
//   ); // 0 bytes of data, rent exempt balance

//   const transaction = new Transaction().add(
//     SystemProgram.createAccount({
//       fromPubkey: keypair2.publicKey, // The payer's public key (payer funds the account creation)
//       newAccountPubkey: newAccount.publicKey, // New account public key
//       lamports: lamportsRequired, // The amount of lamports to fund the new account
//       space: 0, // No additional space required
//       programId: SystemProgram.programId, // System program
//     })
//   );

//   // Send transaction to create the new account
//   const signature = await connection.sendTransaction(
//     transaction,
//     [keypair2, newAccount],
//     { skipPreflight: false, preflightCommitment: "confirmed" }
//   );
//   await connection.confirmTransaction(signature, "confirmed");
//   //console.log(`New system account created: ${newAccount.publicKey.toString()}`);

//   // Call your smart contract with the new account public key
//   await interactWithSmartContract(newAccount.publicKey, newAccount);

//   // Return the public key of the new system account
//   return newAccount;
// }
// // Function to interact with your Solana smart contract (Anchor)
// async function interactWithSmartContract(newAccountPubkey, newAccount) {
//   const idl = await anchor.Program.fetchIdl(programId, provider);
//   const program = new anchor.Program(idl, programId, provider);
//   try {
//     const tx = await program.methods
//       .initializeNewAccount(newAccountPubkey) // Assuming the instruction method is 'initializeNewAccount'
//       .accounts({
//         payer: keypair2.publicKey, // The payer account (signer)
//         newAccount: newAccountPubkey, // The new system account
//         systemProgram: SystemProgram.programId, // System program
//       })
//       .signers([newAccount])
//       .rpc();

//     //console.log("Smart contract transaction signature:", tx);
//   } catch (error) {
//     console.error("Error interacting with smart contract:", error);
//   }
// }

// Endpoint to create an escrow and generate a wallet address
app.post("/api/create-escrow", async (req, res) => {
  const {
    amount,
    currency,
    payerId,
    merchantWalletAddress,
    key,
    initializedWalletAddress,
  } = req.body; // Include payerId from the request body

  try {
    if (currency !== "SOL" && currency !== "USDC") {
      return res
        .status(400)
        .json({ error: "Unsupported currency. Use SOL or USDC." });
    }

    // Generate a unique wallet address based on the currency type
    const walletAddress = createWalletAddress();

    // Generate escrow account address for Solana
    const escrowAccount = Keypair.generate();

    // Load the program IDL

    // Merchant wallet address (you'll get this from your database or frontend)
    const merchantWallet = new anchor.web3.PublicKey(initializedWalletAddress);

    const currencyParam = currency === "SOL" ? { sol: {} } : { sol: {} }; // Assuming USDC has a similar structure

    const sol_platform_wallet = authority;
    const platform_Key = new anchor.web3.PublicKey(sol_platform_wallet);

    //console.log("platform sol wallet...", sol_platform_wallet);

    const newAccount = escrowAccount;

    // try {
    //   const response = await program.methods
    //     .initializeEscrow(
    //       new anchor.BN(amount), // Amount to be stored in escrow
    //       currencyParam, // Dynamic currency type
    //       merchantWallet, // Merchant's wallet address
    //       platform_Key,
    //       payerId
    //     ) // Payer ID to be sent to the smart contract
    //     .accounts({
    //       escrowAccount: escrowAccount.publicKey,
    //       user: provider.wallet.publicKey,
    //       systemProgram: anchor.web3.SystemProgram.programId,
    //     })
    //     .signers([escrowAccount]) // Include escrowAccount as a signer
    //     .rpc();

    //   const escrowAccountInfo = await program.account.escrowAccount.fetch(
    //     escrowAccount.publicKey
    //   );

    //   //console.log("Escrow account initialized:", escrowAccountInfo);
    // } catch (error) {
    //   //console.log("error :", error);
    // }

    req.session.user = payerId;
    req.session.tx = escrowAccount;

    req.saveTransactionKeypair(escrowAccount);

    req.session.save((err) => {
      if (err) {
        console.error("Error saving session:", err);
      }
    });

    // Create a new payment request
    await PaymentRequest.create({
      key: key, // Ensure this is the correct value
      amount,
      currency,
      payerId, // User's email
      merchantWalletAddress,
      escrowAccount: escrowAccount.publicKey.toString(),
      created_at: new Date(),
      updated_at: new Date(),
    });

    // Return the generated wallet address and escrow address
    res.json({
      walletAddress,
      escrowAddress: escrowAccount.publicKey.toString(),
      sss: req.sessionID,
      amount,
      message: "Escrow account created successfully.",
      platform: sol_platform_wallet,
      merchant: initializedWalletAddress,
      accountPub: newAccount.publicKey.toString(),
    });
    //console.log(req.sessionID, "...................... tx: ", req.session);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to create escrow account." });
  }
});

const mintAddress = process.env.USDC_MINT_ADDRESS; // The USDC mint addres

// Function to get the minimum balance required for an account to be rent-exempt
async function getRentExemptMinimum(connection) {
  const rentExemptAmount = await connection.getMinimumBalanceForRentExemption(
    0
  ); // 0 size for normal accounts
  //console.log(`Rent-exempt minimum: ${rentExemptAmount} lamports`);
  return rentExemptAmount;
}

// Function to check the balance of an account
async function checkBalance(connection, publicKey) {
  const balance = await connection.getBalance(publicKey);
  //console.log(
  //   `Balance of ${publicKey.toString()}: ${balance / LAMPORTS_PER_SOL} SOL`
  // );
  return balance;
}

async function fundRecipientIfNeeded(
  connection,
  from,
  to,
  minRentExemptAmount
) {
  const balance = await checkBalance(connection, to);

  // Ensure the recipient remains rent-exempt after the transfer
  const minimumPostTransferBalance = minRentExemptAmount + 5000; // Ensure recipient stays rent-exempt

  if (balance < minimumPostTransferBalance) {
    const lamportsToTransfer = minimumPostTransferBalance - balance;
    //console.log(
    //   `Funding ${to.toString()} with ${(
    //     lamportsToTransfer / LAMPORTS_PER_SOL
    //   ).toFixed(6)} SOL`
    // );

    const transaction = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: from.publicKey,
        toPubkey: to,
        lamports: lamportsToTransfer,
      })
    );

    transaction.feePayer = from.publicKey;
    const { blockhash } = await connection.getLatestBlockhash();
    transaction.recentBlockhash = blockhash;

    transaction.sign(from);
    await sendAndConfirmTransaction(connection, transaction, [from]);

    //console.log(`Funded ${to.toString()} successfully.`);
  } else {
    //console.log("Recipient account has enough funds.");
  }
}

const transferSOL = async (
  from,
  signer,
  to,
  amount,
  feePayer,
  platform,
  platformAmt
) => {
  // Create a connection to the cluster

  // Log the keypairs to ensure they are defined
  //console.log("From Public Key:", from.toString());
  //console.log("To Public Key:", to.toString());
  //console.log("Fee Payer Public Key:", feePayer.publicKey.toString());

  // Create a transaction
  const transaction = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: from,
      toPubkey: to,
      lamports: amount, // Convert SOL to lamports
    }),

    // Second transfer to platform
    SystemProgram.transfer({
      fromPubkey: from,
      toPubkey: platform,
      lamports: platformAmt, // Convert SOL to lamports for platform
    })
  );

  // Set the fee payer for the transaction
  transaction.feePayer = feePayer.publicKey;

  // Get recent blockhash and set it to the transaction
  const { blockhash } = await connection.getLatestBlockhash();
  transaction.recentBlockhash = blockhash;

  // Sign the transaction with both the sender and fee payer
  transaction.sign(signer); // Sign with the sender's Keypair

  // Send and confirm the transaction
  try {
    const signature = await sendAndConfirmTransaction(connection, transaction, [
      signer,
      feePayer,
    ]);
    //console.log("Transfer successful! Signature:", signature);
    return signature;
  } catch (error) {
    console.error("Transfer failed:", error);
    return null;
  }
};

async function generateReceiptEmailContent({
  name,
  payment_request_id,
  amount_platform,
  amount_merchant,
  transaction_hash,
  payer_email,
  merchantWalletAddress,
  status,
  merchant,
  link,
}) {
  return `
  <!DOCTYPE html>
  <html>
  <head>
      <title>Transaction Receipt</title>
      <style>
          body {
              font-family: Arial, sans-serif;
              margin: 0;
              padding: 0;
              background-color: #f4f4f4;
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
              background-color: #4CAF50;
              padding: 10px;
              text-align: center;
              color: #ffffff;
          }
          .content {
              padding: 20px;
              color: #333333;
          }
          .footer {
              background-color: #4CAF50;
              padding: 10px;
              text-align: center;
              color: #ffffff;
          }
          .table-container {
              margin-top: 20px;
          }
          table {
              width: 100%;
              border-collapse: collapse;
              margin: 20px 0;
          }
          table, th, td {
              border: 1px solid #ddd;
              padding: 8px;
          }
          th {
              background-color: #f2f2f2;
              text-align: left;
          }
          td {
              text-align: left;
          }
      </style>
  </head>
  <body>
      <div class="container">
          <div class="header">
              <h1>Transaction Receipt</h1>
          </div>
          <div class="content">
              <p>Thank you for your payment. Below are the details of your transaction:</p>
              <div class="table-container">
                  <table>
                      <tr>
                          <th>Field</th>
                          <th>Value</th>
                      </tr>
                      <tr>
                          <td><strong>Module</strong></td>
                          <td>${link}</td>
                      </tr>
                      <tr>
                          <td><strong>Name (payer)</strong></td>
                          <td>${name}</td>
                      </tr>
                      <tr>
                          <td><strong>Transaction key</strong></td>
                          <td>${payment_request_id}</td>
                      </tr>
                      <tr>
                          <td><strong>Amount Paid to merchant</strong></td>
                          <td>${amount_merchant} SOL</td>
                      </tr>
                      <tr>
                          <td><strong>Transaction Ref</strong></td>
                          <td>${transaction_hash}</td>
                      </tr>
                      <tr>
                          <td><strong>Payer Email</strong></td>
                          <td>${payer_email}</td>
                      </tr>
                      <tr>
                      <td><strong>merchant Email</strong></td>
                      <td>${merchant}</td>
                      </tr>
                      <tr>
                          <td><strong>Merchant Wallet Address</strong></td>
                          <td>${merchantWalletAddress}</td>
                      </tr>
                      <tr>
                          <td><strong>Status</strong></td>
                          <td>${status}</td>
                      </tr>
                  </table>
              </div>
          </div>
          <div class="footer">
              <p>&copy; 2024 DexPay. All rights reserved.</p>
          </div>
      </div>
  </body>
  </html>
  `;
}

async function sendEmailWithAttachment(payer, toEmail, pdfBuffer) {
  // Email options
  const mailOptions = {
    from: "dexpay.dec@gmail.com",
    to: toEmail,
    subject: "Your Payment Receipt",
    html: `Hello ${payer} Please find attached receipt for the recent transaction.\n ${pdfBuffer}`,
  };

  // Send the email
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      //console.log("Error sending email:", error);
    } else {
      //console.log("Email sent:", info.response);
    }
  });
}

async function generatePDF(htmlContent) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();

  // Load the HTML content
  await page.setContent(htmlContent, { waitUntil: "networkidle0" });

  // Generate the PDF and return it as a buffer
  const pdfBuffer = await page.pdf({
    format: "A4",
    printBackground: true,
  });

  await browser.close();
  return pdfBuffer;
}

app.post("/download-receipt", async (req, res) => {
  const { key, amount_merchant, tx, payerEmail, merchant, merchant_email } =
    req.body;

  try {
    const user = await User.findOne({ where: { email: payerEmail } });
    const merchantPublicKey = new PublicKey(merchant);

    const emailContent = generateReceiptEmailContent(
      `${user.firstName} ${user.lastName}`,
      key,
      "amount_platform",
      amount_merchant,
      tx, // Placeholder for actual transaction hash
      payerEmail,
      merchantPublicKey.toString(),
      merchant_email
    );

    const pdfBuffer = await generatePDF(emailContent);

    // Set headers to force download and send the PDF buffer
    res.set({
      "Content-Type": "application/pdf",
      "Content-Disposition": 'attachment; filename="receipt.pdf"',
      "Content-Length": pdfBuffer.length,
    });

    res.send(pdfBuffer); // Send the buffer as response
  } catch (error) {
    console.error("Error completing download:", error);
    res.status(500).json({
      error: "Failed to complete download",
      details: error.message,
      success: false,
    });
  }
});
// Post request handler
app.post("/complete-escrow", async (req, res) => {
  //console.log("Request Body:", req.body);

  // Destructure request body
  const {
    amount,
    escrowAccount,
    initialized_merchant_address,
    platform,
    currency,
    key,
    payerEmail,
    merchant,
    newPub,
    merchant_email,
    link,
  } = req.body;

  try {
    const signer = await req.getTransactionKeypair();

    console.log(signer);

    // Check for required fields
    if (!escrowAccount || !merchant) {
      return res
        .status(400)
        .json({ error: "Missing required fields", success: false });
    }

    console.log("log234", signer);

    if (!signer) {
      return res
        .status(400)
        .json({ error: "No valid transaction session", success: false });
    }

    // Convert signer secretKey to Keypair
    const secretKey = new Uint8Array(Object.values(signer._keypair.secretKey));
    const keypair = Keypair.fromSecretKey(secretKey);

    // const programId = new anchor.web3.PublicKey(process.env.RUST_PROGRAM_ID);
    // // Load Anchor program
    // const idl = await anchor.Program.fetchIdl(programId, provider);
    // const program = new anchor.Program(idl, programId, provider);

    // Fetch the balance of the escrow account in SOL
    const escrowPublicKey = new PublicKey(escrowAccount);
    const escrowBalanceLamports = await provider.connection.getBalance(
      escrowPublicKey
    );
    const escrowBalanceSOL = escrowBalanceLamports / LAMPORTS_PER_SOL;

    if (escrowBalanceSOL === 0) {
      return res
        .status(400)
        .json({ error: "You haven't made any deposit", success: false });
    }

    const PubKey = new PublicKey(newPub);
    const pubBalanceLamports = await provider.connection.getBalance(PubKey);
    const pubBalanceSOL = pubBalanceLamports / LAMPORTS_PER_SOL;

    if (escrowBalanceSOL < amount) {
      const remainder = amount - escrowBalanceSOL;
      return res.status(400).json({
        error: `Insufficient payment. you paid less than the amount required`,
        success: false,
      });
    }

    //console.log(`escrow Account Balance: ${escrowBalanceSOL} SOL`);

    // Set platform wallet based on currency
    let platformWalletAddress;
    if (currency === "SOL") {
      platformWalletAddress = process.env.PLATFORM_WALLET_SOL;
    } else {
      return res
        .status(400)
        .json({ error: "Unsupported currency type", success: false });
    }

    // Merchant and platform public keys
    const merchantPublicKey = new PublicKey(merchant);
    const merchantBalanceLamports = await provider.connection.getBalance(
      merchantPublicKey
    );

    const merchantBalanceSOL = merchantBalanceLamports / LAMPORTS_PER_SOL;
    //console.log(`merchant Account Balance: ${merchantBalanceSOL} SOL`);

    const platformPublicKey = new PublicKey(platform);

    const platformBalanceLamports = await provider.connection.getBalance(
      platformPublicKey
    );

    const platformBalanceSOL = platformBalanceLamports / LAMPORTS_PER_SOL;
    //console.log(`platform Account Balance: ${platformBalanceSOL} SOL`);

    const LAMPORTS_PER_SOL2 = BigInt(1000000000); // 1 SOL = 1,000,000,000 lamports

    // Convert the amount to lamports (BigInt)
    const amountLamports = BigInt(amount * Number(LAMPORTS_PER_SOL2)); // amount is still a float here

    // Use integer math for the platform fee calculation (2%)
    const platformFeePercentage = BigInt(2); // Represent 2% as BigInt
    const platformFeeLamports =
      (amountLamports * platformFeePercentage) / BigInt(100); //

    const rentFeePercentage = BigInt(6); // Represent 6% as BigInt
    const rentFeeLamports = (amountLamports * rentFeePercentage) / BigInt(100); //

    const charges = rentFeeLamports + platformFeeLamports;

    const merchantAmountLamports = amountLamports - charges;

    if (escrowBalanceLamports < platformFeeLamports + merchantAmountLamports) {
      return res.status(400).json({
        error: "Insufficient deposit made",
        success: false,
      });
    }

    const user = await User.findOne({ where: { email: payerEmail } });

    const keypairBalance = await provider.connection.getBalance(
      keypair.publicKey
    );
    //console.log("Keypair balance:", keypairBalance / LAMPORTS_PER_SOL, "SOL");

    try {
      // Get the rent-exempt minimum balance
      const rentExemptAmount = await getRentExemptMinimum(connection);

      // Check if the recipient is rent-exempt, and fund if necessary
      await fundRecipientIfNeeded(
        connection,
        keypair2,
        merchantPublicKey,
        rentExemptAmount
      );

      const tx = await transferSOL(
        escrowPublicKey,
        keypair,
        merchantPublicKey,
        merchantAmountLamports,
        keypair2,
        platformPublicKey,
        charges
      );
      // After successful transfer, store transaction details
      const amount_platform = (amount * 0.08).toFixed(6); // Platform fee in SOL
      const amount_merchant = (amount * 0.92).toFixed(6); // Merchant's amount in SOL
      const payer_id = payerEmail;

      if (tx !== null) {
        await Notification.create({
          userEmail: payerEmail,
          title: "New Payment",
          message: `Your payment of ${amount_merchant} SOL has been completed successfully.`,
        });
        // Save transaction to the database
        const details = await Transaction2.create({
          payment_request_id: key,
          total_amount: escrowBalanceSOL,
          amount_platform,
          amount_merchant,
          transaction_hash: tx, // Placeholder for actual transaction hash
          payer_email: payerEmail,
          merchantWalletAddress: merchantPublicKey.toString(),
          status: "Completed",
          created_at: new Date(),
          updated_at: new Date(),
        });
        //console.log("Escrow completed successfully");

        const emailContent = await generateReceiptEmailContent({
          name: `${user.firstName} ${user.lastName}`,
          payment_request_id: key,
          amount_platform,
          amount_merchant,
          transaction_hash: tx, // Placeholder for actual transaction hash
          payer_email: payerEmail,
          merchantWalletAddress: merchantPublicKey.toString(),
          status: "Completed",
          merchant: merchant_email,
          link,
        });

        sendEmailWithAttachment(
          `${user.firstName} ${user.lastName}`,
          payerEmail,
          emailContent
        );

        const message = `${link} Credit Alert\n ${payerEmail} just made a payment of ${amount_merchant} to your payment link "${link}"`;

        const emailContent2 = generateEmailContent(
          `${user.firstName} ${user.lastName}`,
          message
        );
        await sendEmail(merchant_email, emailContent2);

        await Notification.create({
          userEmail: merchant_email,
          title: "Credit alert",
          message: `A payment of ${amount_merchant} SOL has been made to module ${link}.`,
        });

        req.session.destroy((err) => {
          if (err) {
            return console.error("Failed to destroy session", err);
          }
          //console.log("Session destroyed");
        });

        res.status(200).json({
          message: "Escrow completed successfully",
          success: true,
          details,
        });
      } else console.error("no transaction hash");
    } catch (error) {
      console.error("Error completing escrow:", error);

      if (error instanceof anchor.web3.SendTransactionError) {
        console.error("Transaction logs:", error.getLogs());
      }
    }
  } catch (error) {
    console.error("Error completing escrow:", error);
    res.status(500).json({
      error: "Failed to complete escrow",
      details: error.message,
      success: false,
    });
  }
});

const refundSOL = async (from, signer, to, amount, feePayer) => {
  // Create a connection to the cluster

  // Log the keypairs to ensure they are defined
  //console.log("From Public Key:", from.toString());
  //console.log("To Public Key:", to.toString());
  //console.log("Fee Payer Public Key:", feePayer.publicKey.toString());

  // Create a transaction
  const transaction = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: from,
      toPubkey: to,
      lamports: amount, // Convert SOL to lamports
    })
  );

  // Set the fee payer for the transaction
  transaction.feePayer = feePayer.publicKey;

  // Get recent blockhash and set it to the transaction
  const { blockhash } = await connection.getLatestBlockhash();
  transaction.recentBlockhash = blockhash;

  // Sign the transaction with both the sender and fee payer
  transaction.sign(signer); // Sign with the sender's Keypair

  // Send and confirm the transaction
  try {
    const signature = await sendAndConfirmTransaction(connection, transaction, [
      signer,
      feePayer,
    ]);
    //console.log("Transfer successful! Signature:", signature);
    req.session.destroy((err) => {
      if (err) {
        return console.error("Failed to destroy session", err);
      }
      //console.log("Session destroyed");
    });
    return signature;
  } catch (error) {
    console.error("Transfer failed:", error);
    return null;
  }
};

app.post("/refund-escrow", async (req, res) => {
  const { key, escrowAddress, refundWalletAddress, refundAmount, payerEmail } =
    req.body;

  // Check for required fields
  if (!refundWalletAddress || !escrowAddress) {
    return res
      .status(400)
      .json({ error: "Missing required fields", success: false });
  }

  const signer = req.getTransactionKeypair();

  if (!signer) {
    return res
      .status(400)
      .json({ error: "No valid transaction session", success: false });
  }

  try {
    // Convert signer secretKey to Keypair
    const secretKey = new Uint8Array(Object.values(signer._keypair.secretKey));
    const keypair = Keypair.fromSecretKey(secretKey);

    // Fetch the balance of the escrow account in SOL
    const escrowPublicKey = new PublicKey(escrowAddress);
    const escrowBalanceLamports = await provider.connection.getBalance(
      escrowPublicKey
    );
    const escrowBalanceSOL = escrowBalanceLamports / LAMPORTS_PER_SOL;

    if (escrowBalanceSOL === 0) {
      return res
        .status(400)
        .json({ error: "You haven't made any deposit", success: false });
    }

    // Merchant and platform public keys
    const merchantPublicKey = new PublicKey(refundWalletAddress);
    const merchantBalanceLamports = await provider.connection.getBalance(
      merchantPublicKey
    );

    const merchantBalanceSOL = merchantBalanceLamports / LAMPORTS_PER_SOL;
    //console.log(`merchant Account Balance: ${merchantBalanceSOL} SOL`);

    if (escrowBalanceSOL < refundAmount) {
      const remainder = refundAmount - escrowBalanceSOL;
      return res.status(400).json({
        error: `Insufficient payment. you paid less than the amount required`,
        success: false,
      });
    }

    const LAMPORTS_PER_SOL2 = BigInt(1000000000); // 1 SOL = 1,000,000,000 lamports

    // Convert the amount to lamports (BigInt)
    const amountLamports = BigInt(refundAmount * Number(LAMPORTS_PER_SOL2)); // amount is still a float here

    if (escrowBalanceLamports < amountLamports) {
      return res.status(400).json({
        error: "Insufficient funds for reversal",
        success: false,
      });
    }

    try {
      const tx = await refundSOL(
        escrowPublicKey,
        keypair,
        merchantPublicKey,
        amountLamports,
        keypair2
      );

      if (tx !== null) {
        await Notification.create({
          userEmail: payerEmail,
          title: "New Payment",
          message: `A refund of ${refundAmount} SOL has been initiated by you.`,
        });
        // Save transaction to the database
        const details = await Refund.create({
          payment_request_id: key,
          total_amount: refundAmount,
          transaction_hash: tx, // Placeholder for actual transaction hash
          initiator_email: payerEmail,
          merchantWalletAddress: merchantPublicKey.toString(),
          status: "Completed",
          created_at: new Date(),
          updated_at: new Date(),
        });
        //console.log("Refund completed successfully");

        res.status(200).json({
          message: "Refund completed successfully",
          success: true,
          details,
        });
      } else console.error("no transaction hash");
    } catch (error) {
      console.error("Error completing Refund:", error);

      if (error instanceof anchor.web3.SendTransactionError) {
        console.error("Transaction logs:", error.getLogs());
      }
    }
  } catch (error) {
    console.error("Error completing refund:", error);
    res.status(500).json({
      error: "Failed to complete refund",
      details: error.message,
      success: false,
    });
  }
});

app.post("/initialize-tx-session", (req, res) => {
  const { pair, auth, amount, merchant } = req.body;
  try {
    req.session.auth = auth;
    req.session.tx_sesh_N = pair;
    req.session.amount = amount;
    req.session.merchant = merchant;
    //console.log(req.sessionID);
    res.send({ session: req.sessionID });
  } catch (err) {
    console.error(err);
  }
});

function isAuthenticated(req, res, next) {
  if (req.session.auth) {
    return next(); // User is authenticated, proceed to next middleware
  }
  res.status(401).json({ message: "Unauthorized access", success: false });
}

// Protected route example
app.get("/tx-session-auth", (req, res) => {
  try {
    if (!req.session.auth) {
      return res
        .status(401)
        .json({ message: "Unauthorized access", success: false }); // User is authenticated, proceed to next middleware
    }

    //console.log(req.session.auth);
    res.json({
      message: "Here is your session data",
      success: true,
      merchant: req.session.merchant, // Returning session info to the client
      amount: req.session.amount,
    });
  } catch (err) {
    console.error(err);
  }
});

app.post("/tx-session-disable", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "disable failed" });
    }
    res.clearCookie("connect.sid"); // Clear the session cookie
    res.status(200).json({ message: "session disabled successfully" });
  });
});

// 3. Decrypt the data using NaCl
const decryptData = ({
  decodedPhantomPublicKey,
  decodedNonce,
  decodedEncryptedData,
  dappPrivateKey, // Updated variable name for clarity
}) => {
  try {
    // Log and check each key to ensure they are proper Uint8Array
    if (!(decodedPhantomPublicKey instanceof Uint8Array)) {
      // //console.log(
      //   "decodedPhantomPublicKey is not a Uint8Array:",
      //   decodedPhantomPublicKey
      // );
    } else {
      //console.log("decodedPhantomPublicKey is valid.", decodedPhantomPublicKey);
    }

    if (!(decodedNonce instanceof Uint8Array)) {
      //console.log("decodedNonce is not a Uint8Array:", decodedNonce);
    } else {
      //console.log("decodedNonce is valid.", decodedNonce);
    }

    if (!(decodedEncryptedData instanceof Uint8Array)) {
      //console.log(
      //   "decodedEncryptedData is not a Uint8Array:",
      //   decodedEncryptedData
      // );
    } else {
      //console.log("decodedEncryptedData is valid.", decodedEncryptedData);
    }

    if (!(dappPrivateKey instanceof Uint8Array)) {
      //console.log("dappPrivateKey is not a Uint8Array:", dappPrivateKey);
    } else {
      //console.log("dappPrivateKey is valid.", dappPrivateKey);
    }

    // Attempt decryption
    const decryptedData = nacl.box.open(
      decodedEncryptedData, // Encrypted data from the wallet
      decodedNonce, // Nonce from the wallet
      decodedPhantomPublicKey, // Phantom wallet public key
      dappPrivateKey // Pass the DApp's private key correctly
    );

    if (!decryptedData) {
      //console.log("Failed to decrypt the data.");
      return null;
    }

    // Convert the decrypted data to a readable format
    const decodedString = new TextDecoder().decode(decryptedData);
    //console.log("Decrypted data:", decodedString);
    return decodedString;
  } catch (error) {
    console.error("Decryption error:", error);
    //console.log("An error occurred during decryption.");
    return null;
  }
};

// 4. Handle the decrypted data (e.g., extract wallet address or other information)
const handleDecryptedData = (decodedString) => {
  try {
    const walletData = JSON.parse(decodedString);

    const walletAddress = walletData.public_key;
    //console.log(`User Wallet Address: ${walletAddress}`); // Corrected //console.log message

    // Additional actions based on wallet address
    return { publicKey: walletData.public_key, session: walletData.session };
  } catch (err) {
    console.error("Error parsing decrypted data:", err);
    //console.log(
    //   "Error parsing decrypted data. Please check the response format."
    // );
    return null;
  }
};

function isValidBase64(str) {
  // Check if the string length is a multiple of 4
  if (str.length % 4 !== 0) return false;

  // Check for valid base64 characters
  const base64Regex = /^[A-Za-z0-9+/]+={0,2}$/;
  return base64Regex.test(str);
}

app.post("/getPubkey", async (req, res) => {
  const { decodedPhantomPublicKey, decodedNonce, decodedEncryptedData } =
    req.body;
  const signer = req.session.tx_sesh_N;
  if (!signer) {
    console.error("No signer");
    return res.status(401).json({ success: false, message: "no signer found" });
  }
  //console.log(signer.publicKey)
  try {
    const secretKey = new Uint8Array(Object.values(signer.secretKey));
    const keypair = secretKey;

    const handlePhantomResponse = (dappPrivateKey) => {
      //console.log(dappPrivateKey);
      const decryptedString = decryptData({
        decodedPhantomPublicKey: new Uint8Array(
          Object.values(decodedPhantomPublicKey)
        ),
        decodedNonce: new Uint8Array(Object.values(decodedNonce)),
        decodedEncryptedData: new Uint8Array(
          Object.values(decodedEncryptedData)
        ),
        dappPrivateKey, // Pass the DApp's private key here
      });
      if (decryptedString) {
        const walletAddress = handleDecryptedData(decryptedString);
        return walletAddress;
      }
    };
    const details = handlePhantomResponse(keypair);
    //console.log(details);

    const from = new PublicKey(details.publicKey);

    const amount = req.session.amount;
    const merchant = req.session.merchant;
    const platform = authority;

    //console.log(platform);
    //console.log(merchant);

    const platformPublicKey = new PublicKey(platform);
    const merchantPublicKey = new PublicKey(merchant);

    const amount_platform = (amount * 0.08).toFixed(6); // Platform fee in SOL
    const amount_merchant = (amount * 0.92).toFixed(6); // Merchant's amount in SOL

    const transaction = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: from,
        toPubkey: merchantPublicKey,
        lamports: amount_merchant * LAMPORTS_PER_SOL, // Convert SOL to lamports
      }),

      // Second transfer to platform
      SystemProgram.transfer({
        fromPubkey: from,
        toPubkey: platformPublicKey,
        lamports: amount_platform * LAMPORTS_PER_SOL, // Convert SOL to lamports for platform
      })
    );
    transaction.feePayer = from;
    const { blockhash } = await connection.getLatestBlockhash();
    transaction.recentBlockhash = blockhash;

    // Step 3: Serialize the transaction
    const serializedTransaction = transaction.serialize({
      requireAllSignatures: false,
    });
    const base64Transaction = serializedTransaction.toString("base64");
    //console.log(isValidBase64(base64Transaction))

    res.send({
      success: true,
      message: "decryption successful",
      walletDetails: details,
      transaction: base64Transaction,
      depk: signer.publicKey,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "disable failed" });
  }
});

// Endpoint to update email verification status
app.put("/verify/email/:email", async (req, res) => {
  const email = req.params.email;
  //console.log(email);
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

// Endpoint to update phone number verification status

app.post("/change-password", async (req, res) => {
  const { email, oldPassword, newPassword } = req.body;
  //console.log(oldPassword);

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
      await Transaction2.update(
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

// app.delete("/delete-account", async (req, res) => {
//   const { email } = req.body;

//   try {
//     // Begin a transaction
//     await sequelize.transaction(async (t) => {
//       // Delete from User table
//       await User.destroy({ where: { email }, transaction: t });

//       // Delete from BankDetail table
//       await BankDetail.destroy({ where: { userEmail: email }, transaction: t });

//       // Delete from Revenue table
//       await Revenue.destroy({ where: { email }, transaction: t });

//       // Delete from Transaction table
//       await Transaction.destroy({ where: { email }, transaction: t });

//       // Delete from Verification table
//       await Verification.destroy({ where: { email }, transaction: t });

//       // Delete from Event table
//       await Event.destroy({ where: { creatorEmail: email }, transaction: t });

//       // No need to commit here, Sequelize handles commit automatically if there's no error
//     });

//     res.status(200).json({
//       message: `Account with email ${email} deleted successfully from all tables.`,
//     });
//   } catch (error) {
//     console.error("Error deleting account:", error);
//     res.status(500).json({ error: "Error deleting account." });
//   }
// });

app.post("/notifications", async (req, res) => {
  const { email } = req.query;

  try {
    const notifications = await Notification.findAll({
      where: { userEmail: email, read: false },
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

sequelize
  .sync({ alter: true })
  .then(() => {
    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  })
  .catch((err) => {
    console.error("Unable to connect to the database:", err);
  });
