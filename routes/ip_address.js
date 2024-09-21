const express = require('express');
const db = require('../config/db');
const ApiResponse = require('../utils/ApiResponse');
const authenticateToken = require('../middlewares/authenticateToken');

const router = express.Router();

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);
  ApiResponse.error(err.message || 'Internal server error', err.statusCode || 500).send(res);
};

// Insert IP Address
router.post('/', authenticateToken, async (req, res, next) => {
  const { ip } = req.body;
  const user_id = req.user.id;

  try {
    await db.query('INSERT INTO ip_address (ip, user_id) VALUES (?, ?)', [ip, user_id]);
    ApiResponse.success('IP address added successfully', null, 201).send(res);
  } catch (error) {
    next(error);
  }
});

// Delete IP Address
router.delete('/:id', authenticateToken, async (req, res, next) => {
  const { id } = req.params;
  const user_id = req.user.id;

  try {
    const [result] = await db.query('DELETE FROM ip_address WHERE id = ? AND user_id = ?', [id, user_id]);
    if (result.affectedRows === 0) {
      return ApiResponse.error('IP address not found or unauthorized', 404).send(res);
    }
    ApiResponse.success('IP address deleted successfully').send(res);
  } catch (error) {
    next(error);
  }
});

// Get IP Addresses for a User
router.get('/', authenticateToken, async (req, res, next) => {
  const user_id = req.user.id;

  try {
    const [rows] = await db.query('SELECT * FROM ip_address WHERE user_id = ?', [user_id]);
    ApiResponse.success('IP addresses retrieved successfully', rows).send(res);
  } catch (error) {
    next(error);
  }
});

// Update IP check status
router.post('/ipcheck', authenticateToken, async (req, res, next) => {
  const user_id = req.user.id;
  const { check } = req.body;

  if (check !== 0 && check !== 1) {
    return ApiResponse.error('Invalid value for check. Must be 0 or 1.', 400).send(res);
  }

  try {
    const [result] = await db.query('UPDATE users SET `ipchecks` = ? WHERE id = ?', [check, user_id]);

    if (result.affectedRows === 0) {
      return ApiResponse.error('User not found', 404).send(res);
    }

    ApiResponse.success('Check value updated successfully').send(res);
  } catch (error) {
    next(error);
  }
});

// Get IP check status
router.get('/ipcheck', authenticateToken, async (req, res, next) => {
  const user_id = req.user.id;

  try {
    const [rows] = await db.query('SELECT `ipchecks` FROM users WHERE id = ?', [user_id]);

    if (rows.length === 0) {
      return ApiResponse.error('User not found', 404).send(res);
    }

    ApiResponse.success('IP check value retrieved successfully', { check: rows[0].ipchecks }).send(res);
  } catch (error) {
    next(error);
  }
});

// Apply error handling middleware
router.use(errorHandler);

module.exports = router;