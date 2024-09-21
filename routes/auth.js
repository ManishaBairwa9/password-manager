const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../config/db");
const checkIpAddress = require("../middlewares/checkIpAddress");
const ApiResponse = require("../utils/ApiResponse");
const router = express.Router();
const crypto = require("crypto");

// Use environment variables for sensitive information
const JWT_SECRET = process.env.JWT_SECRET || "goldenheart"; // Fallback for development
const JWT_EXPIRATION = "1h";

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  const statusCode = err.statusCode || 500;
  const message = err.message || "Internal Server Error";
  ApiResponse.error(message, statusCode).send(res);
};

// Utility function to generate random key
const generateRandomKey = () => crypto.randomBytes(16).toString("hex");

// Utility function to hash password
const hashPassword = async (password) => await bcrypt.hash(password, 10);

// Register route

router.post("/register", async (req, res, next) => {
  const { email, password } = req.body;
  const ipAddress = req.body.ip;

  if (!ipAddress) {
    return ApiResponse.error("Cannot proceed without IP address", 400).send(
      res
    );
  }

  try {
    const hashedPassword = await hashPassword(password);
    const conn = await db.getConnection();

    try {
      await conn.beginTransaction();

      const [userResult] = await conn.query(
        "INSERT INTO users (email, password) VALUES (?, ?)",
        [email, hashedPassword]
      );
      const userId = userResult.insertId;

      await conn.query("INSERT INTO ip_address (user_id, ip) VALUES (?, ?)", [
        userId,
        ipAddress,
      ]);

      const randomKey = generateRandomKey();
      await conn.query("INSERT INTO enkeys (user_id, `key`) VALUES (?, ?)", [
        userId,
        randomKey,
      ]);

      await conn.commit();

      ApiResponse.success("User registered successfully", { userId }, 201).send(
        res
      );
    } catch (error) {
      await conn.rollback();
      throw error;
    } finally {
      conn.release();
    }
  } catch (error) {
    next(error);
  }
});

// Login route
router.post("/login", checkIpAddress, async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (rows.length === 0) {
      return ApiResponse.error("User not found", 404).send(res);
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return ApiResponse.error("Invalid credentials", 401).send(res);
    }

    const token = jwt.sign({ id: user.id }, JWT_SECRET, {
      expiresIn: JWT_EXPIRATION,
    });

    ApiResponse.success("Login successful", { token }).send(res);
  } catch (error) {
    next(error);
  }
});

// Apply error handling middleware
router.use(errorHandler);

module.exports = router;
