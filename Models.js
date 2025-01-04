const { Sequelize, DataTypes } = require("sequelize");
require("dotenv").config();
const session = require('express-session');
const SequelizeStore = require('connect-session-sequelize')(session.Store);

// Initialize Sequelize connection (adjust with your own DB details)
// const sequelize = new Sequelize(
//   process.env.DB_NAME2,
//   process.env.USER,
//   process.env.PASSWORD,
//   {
//     host: process.env.DB_HOST2,
//     dialect: "postgres",
//     // protocol: "postgres",
//     dialectOptions: {
//       ssl: {
//         require: true,
//         rejectUnauthorized: false, // This line is important for connecting to Supabase
//       },
//     },
//     port: 6543, // Default PostgreSQL port
//     logging: false,
//   }
// );

// const sequelize = new Sequelize(process.env.AI_DB, {
//   dialect: 'postgres',
//   ssl: true,
//   dialectOptions: {
//       ssl: {
//           require: true, // Enable SSL
//           rejectUnauthorized: false, // Allow self-signed certificates
//       },
//   },
//   logging: false, // Disable query logging
// });

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: process.env.DB_DIALECT,
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false,
      },
    },
  }
);

// Initialize the session store
const sessionStore = new SequelizeStore({
  db: sequelize,
  tableName: 'user_sessions', // Optional: Customize the table name
  checkExpirationInterval: 15 * 60 * 1000, // Cleanup expired sessions every 15 minutes
  expiration: 30 * 24 * 60 * 60 * 1000, // 30 days
});

// Define User (simple) Model
const simpleUser = sequelize.define("simpleUser", {
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
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

// Define User (Merchant) Model
const User = sequelize.define(
  "User",
  {
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
      allowNull: true,
    },
  },
  {
    tableName: "users",
    timestamps: false,
  }
);

// models/PaymentLinks.js

const PaymentLinks = sequelize.define(
  "PaymentLinks",
  {
    amount_fiat: {
      type: DataTypes.FLOAT,
      allowNull: false,
    },
    amount_crypto: {
      type: DataTypes.FLOAT,
      allowNull: false,
    },
    currency: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    wallet_address: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    initializedWalletAddress: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    key: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,  // Add unique constraint here
      primaryKey: true
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    link_name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    status: {
      type: DataTypes.STRING,
      allowNull: false,
      defaultValue: "Pending",
    },
    merchant_id: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    merchant_email: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        isEmail: true,
      },
    },
  },
  {
    // Additional options can be set here
    tableName: "payment_links",
    timestamps: true,
  }
);

// Define Payment Request Model
const PaymentRequest = sequelize.define(
  "PaymentRequest",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true
    },
    key: {
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    amount: {
      type: DataTypes.FLOAT,
      allowNull: false,
    },
    currency: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    payerId: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        isEmail: true,
      },
    },
    merchantWalletAddress: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    escrowAccount: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW,
    },
    updated_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW,
    },
  },
  {
    tableName: "payment_requests",
    timestamps: false,
  }
);



// Define Transaction Model
const Transaction = sequelize.define(
  "Transaction",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    payment_request_id: {
      type: DataTypes.TEXT, // Change to STRING for the key obtained from the frontend
      allowNull: false,
    },
    total_amount: {
      type: DataTypes.FLOAT,
      allowNull: false,
    },
    amount_platform: {
      type: DataTypes.FLOAT,
      allowNull: false,
    },
    amount_merchant: {
      type: DataTypes.FLOAT,
      allowNull: false,
    },
    transaction_hash: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    payer_email: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        isEmail: true,
      },
    },
    merchantWalletAddress: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    status: {
      type: DataTypes.STRING,
      allowNull: false,
      defaultValue: "Pending",
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW,
    },
    confirmed_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    updated_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW,
    },
  },
  {
    tableName: "transaction",
    timestamps: false,
  }
);

const Refund = sequelize.define(
  "Refund",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    payment_request_id: {
      type: DataTypes.TEXT, // Change to STRING for the key obtained from the frontend
      allowNull: false,
    },
    total_amount: {
      type: DataTypes.FLOAT,
      allowNull: false,
    },
    transaction_hash: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    initiator_email: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        isEmail: true,
      },
    },
    merchantWalletAddress: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    status: {
      type: DataTypes.STRING,
      allowNull: false,
      defaultValue: "Pending",
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW,
    },
    updated_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW,
    },
  },
  {
    tableName: "refund",
    timestamps: false,
  }
);

// Define Cryptocurrency Price Model (Optional)
const CryptoPrice = sequelize.define(
  "CryptoPrice",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    currency: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    price_usd: {
      type: DataTypes.FLOAT,
      allowNull: false,
    },
    price_fiat: {
      type: DataTypes.FLOAT,
      allowNull: false,
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW,
    },
  },
  {
    tableName: "crypto_prices",
    timestamps: false,
  }
);

// Define Log Model (Optional)
const Log = sequelize.define(
  "Log",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    user_id: {
      type: DataTypes.STRING(6), // Updated to match User.id type
      allowNull: true,
      references: {
        model: "users",
        key: "id",
      },
    },
    event_type: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    message: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW,
    },
  },
  {
    tableName: "logs",
    timestamps: false,
  }
);

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

// Define Foreign Key Relationships

// PaymentLinks <-> PaymentRequest

// PaymentRequest <-> Transaction

// User <-> Log (Optional)
User.hasMany(Log, { foreignKey: "user_id" });
Log.belongsTo(User, { foreignKey: "user_id" });

// Export all models
module.exports = {
  sequelize,
  User,
  PaymentRequest,
  Transaction2 : Transaction,
  CryptoPrice,
  Log,
  Notification,
  PaymentLinks,
  simpleUser,
  Refund,
  sessionStore
};
