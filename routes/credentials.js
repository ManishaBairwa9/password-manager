const express = require('express');
const db = require('../config/db');
const { encrypt, decrypt } = require('../utils/encryption');
const ApiResponse = require('../utils/ApiResponse');
const authenticateToken = require('../middlewares/authenticateToken');

const router = express.Router();

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);
  ApiResponse.error(err.message || 'Internal server error', err.statusCode || 500).send(res);
};

// Post credentials
router.post('/', authenticateToken, async (req, res, next) => {
  const { name, link, password } = req.body;
  const userId = req.user.id;

  try {
    const encryptedName = await encrypt(name, userId);
    const encryptedLink = await encrypt(link, userId);
    const encryptedPassword = await encrypt(password, userId);

    await db.query(
      'INSERT INTO credentials (name, link, password, user_id) VALUES (?, ?, ?, ?)',
      [encryptedName, encryptedLink, encryptedPassword, userId]
    );

    ApiResponse.success('Credentials added successfully', null, 201).send(res);
  } catch (error) {
    next(error);
  }
});

// Get credentials
router.get('/', authenticateToken, async (req, res, next) => {
  const userId = req.user.id;

  try {
    const [rows] = await db.query('SELECT * FROM credentials WHERE user_id = ?', [userId]);

    const decryptedRows = await Promise.all(rows.map(async (row) => {
        try {
          return {
            id: row.id,
            name: await decrypt(row.name, userId).catch(() => null), // if decryption fails, set to null
            link: await decrypt(row.link, userId).catch(() => null),
            password: await decrypt(row.password, userId).catch(() => null)
          };
        } catch (error) {
          console.error('Error decrypting row:', row.id, error);
          return null; // or handle as you prefer
        }
      }));
      
      // Filter out null values (failed decryption rows) if needed
      const filteredRows = decryptedRows.filter(row => row !== null);
      

    ApiResponse.success('Credentials retrieved successfully', decryptedRows).send(res);
  } catch (error) {
    next(error);
  }
});

// Edit (Update) credentials
router.put('/:id', authenticateToken, async (req, res, next) => {
  const { id } = req.params;
  const { name, link, password } = req.body;
  const userId = req.user.id;

  try {
    const encryptedName = await encrypt(name, userId);
    const encryptedLink = await encrypt(link, userId);
    const encryptedPassword = await encrypt(password, userId);

    const [result] = await db.query(
      'UPDATE credentials SET name = ?, link = ?, password = ? WHERE id = ? AND user_id = ?',
      [encryptedName, encryptedLink, encryptedPassword, id, userId]
    );

    if (result.affectedRows === 0) {
      return ApiResponse.error('Credential not found or unauthorized', 404).send(res);
    }

    ApiResponse.success('Credential updated successfully').send(res);
  } catch (error) {
    next(error);
  }
});

// Delete credentials
router.delete('/:id', authenticateToken, async (req, res, next) => {
  const { id } = req.params;
  const userId = req.user.id;

  try {
    const [result] = await db.query('DELETE FROM credentials WHERE id = ? AND user_id = ?', [id, userId]);

    if (result.affectedRows === 0) {
      return ApiResponse.error('Credential not found or unauthorized', 404).send(res);
    }

    ApiResponse.success('Credential deleted successfully').send(res);
  } catch (error) {
    next(error);
  }
});

// Apply error handling middleware
router.use(errorHandler);

module.exports = router;