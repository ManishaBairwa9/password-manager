const ApiResponse = require('../utils/ApiResponse');
const db = require('../config/db');

/**
 * Middleware to check if the authenticated user is an admin
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const checkAdmin = async (req, res, next) => {
  const userId = req.user.id;

  if (!userId) {
    return ApiResponse.error('User ID not found in request', 401).send(res);
  }

  try {
    const [rows] = await db.query('SELECT is_admin FROM users WHERE id = ?', [userId]);

    if (rows.length === 0) {
      return ApiResponse.error('User not found', 404).send(res);
    }

    const isAdmin = rows[0].is_admin;

    if (isAdmin) {
      next();
    } else {
      ApiResponse.error('Access denied. Only admin users are allowed.', 403).send(res);
    }
  } catch (error) {
    console.error('Error checking admin status:', error);
    ApiResponse.error('Internal server error', 500).send(res);
  }
};

module.exports = checkAdmin;