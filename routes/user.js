const express = require('express');
const db = require('../config/db');
const ApiResponse = require('../utils/ApiResponse');
const authenticateToken = require('../middlewares/authenticateToken');
const checkAdmin = require('../middlewares/checkAdmin');
const bcrypt = require('bcrypt');

const router = express.Router();

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);
  ApiResponse.error(err.message || 'Internal server error', err.statusCode || 500).send(res);
};

// Delete a user (Admin Only)
router.delete('/:id', authenticateToken, checkAdmin, async (req, res, next) => {
  const { id } = req.params;

  try {
    const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [id]);
    if (rows.length === 0) {
      return ApiResponse.error('User not found', 404).send(res);
    }

    await db.query('DELETE FROM users WHERE id = ?', [id]);
    ApiResponse.success('User deleted successfully').send(res);
  } catch (error) {
    next(error);
  }
});

// Get users with pagination (Admin Only)
router.get('', authenticateToken, checkAdmin, async (req, res, next) => {
  const { page = 1, limit = 10 } = req.query;

  const pageNumber = parseInt(page, 10);
  const pageSize = parseInt(limit, 10);

  if (isNaN(pageNumber) || pageNumber < 1 || isNaN(pageSize) || pageSize < 1) {
    return ApiResponse.error('Invalid pagination parameters', 400).send(res);
  }

  const offset = (pageNumber - 1) * pageSize;

  try {
    // Get paginated users
    const [rows] = await db.query('SELECT id, email FROM users LIMIT ? OFFSET ?', [pageSize, offset]);
    
    // Get total count of users
    const [countResult] = await db.query('SELECT COUNT(*) as total FROM users');
    const totalUsers = countResult[0].total;
    
    const totalPages = Math.ceil(totalUsers / pageSize);

    ApiResponse.success('Users retrieved successfully', {
      users: rows,
      pagination: {
        currentPage: pageNumber,
        pageSize: pageSize,
        totalUsers: totalUsers,
        totalPages: totalPages
      }
    }).send(res);
  } catch (error) {
    next(error);
  }
});

//user only
router.delete('/myaccount/delete', authenticateToken, async (req, res, next) => {
    const id = req.user.id;
  
    try {
      const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [id]);
  
      if (rows.length === 0) {
        return ApiResponse.error('User not found', 404).send(res);
      }
  
      // Delete from ip_address table
      await db.query('DELETE FROM ip_address WHERE user_id = ?', [id]);
  
      // Delete from credentials table
      await db.query('DELETE FROM credentials WHERE user_id = ?', [id]);
  
      // Delete from enkeys table
      await db.query('DELETE FROM enkeys WHERE user_id = ?', [id]);
  
      // Delete from users table
      await db.query('DELETE FROM users WHERE id = ?', [id]);
  
      ApiResponse.success('User and related data deleted successfully').send(res);
    } catch (error) {
      next(error);
    }
  });


// Fetch user details
router.get('/myaccount', authenticateToken, async (req, res, next) => {
    const id = req.user.id;

    try {
        const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [id]);

        if (rows.length === 0) {
            return ApiResponse.error('User not found', 404).send(res);
        }

        const user = rows[0];
        ApiResponse.success('User fetched successfully', user).send(res);
    } catch (error) {
        next(error);
    }
});


// Change password
router.put('/myaccount/password', authenticateToken, async (req, res, next) => {
    const id = req.user.id;
    const { currentPassword, newPassword } = req.body;

    try {
        // Fetch the user's current password from the database
        const [rows] = await db.query('SELECT password FROM users WHERE id = ?', [id]);

        if (rows.length === 0) {
            return ApiResponse.error('User not found', 404).send(res);
        }

        const user = rows[0];

        // Compare currentPassword with the stored hashed password
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return ApiResponse.error('Current password is incorrect', 401).send(res);
        }

        // Hash the new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password in the database
        await db.query('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, id]);

        ApiResponse.success('Password updated successfully').send(res);
    } catch (error) {
        next(error);
    }
});


  

// Apply error handling middleware
router.use(errorHandler);

module.exports = router;