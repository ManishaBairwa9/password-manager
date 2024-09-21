const db = require('../config/db');
const ApiResponse = require('../utils/ApiResponse');

/**
 * Middleware to check if the user's IP address is allowed
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const checkIpAddress = async (req, res, next) => {
  const { email } = req.body;
  const userIp = req.ip || req.connection.remoteAddress; // Get the user's IP address from request

  if (!email) {
    return ApiResponse.error('Email is required', 400).send(res);
  }

  if (!userIp) {
    return ApiResponse.error('Unable to determine user IP address', 400).send(res);
  }

  try {
    // Check if the user exists and get the user's id and ipcheck value
    const [users] = await db.query('SELECT id, ipchecks FROM users WHERE email = ?', [email]);
    
    if (users.length === 0) {
      return ApiResponse.error('User not found', 404).send(res);
    }

    const { id: userId, ipchecks: ipCheckEnabled } = users[0];

    // If ipchecks is 0, skip IP address validation
    if (ipCheckEnabled === 0) {
      return next();
    }

    // If ipchecks is 1, validate the IP address
    const [ipAddresses] = await db.query('SELECT * FROM ip_address WHERE user_id = ? AND ip = ?', [userId, userIp]);

    if (ipAddresses.length === 0) {
      return ApiResponse.error('Access denied: IP address not recognized', 403).send(res);
    }

    next(); // Proceed to the login logic if IP exists
  } catch (error) {
    console.error('Error checking IP address:', error);
    ApiResponse.error('Internal server error', 500).send(res);
  }
};

module.exports = checkIpAddress;