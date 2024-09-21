const jwt = require('jsonwebtoken');
const ApiResponse = require('../utils/ApiResponse');

// Use environment variables for sensitive information
const JWT_SECRET = process.env.JWT_SECRET || 'goldenheart'; // Fallback for development

/**
 * Middleware to authenticate and verify JWT tokens
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return ApiResponse.error('No authorization header provided', 401).send(res);
  }

  const [bearer, token] = authHeader.split(' ');

  if (bearer !== 'Bearer' || !token) {
    return ApiResponse.error('Invalid authorization header format', 401).send(res);
  }

  try {
    const decodedToken = jwt.verify(token, JWT_SECRET);
    req.user = decodedToken;
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return ApiResponse.error('Token has expired', 401).send(res);
    } else if (error instanceof jwt.JsonWebTokenError) {
      return ApiResponse.error('Invalid token', 403).send(res);
    } else {
      console.error('JWT verification error:', error);
      return ApiResponse.error('Failed to authenticate token', 500).send(res);
    }
  }
};

module.exports = authenticateToken;