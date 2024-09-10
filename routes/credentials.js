const express = require('express');
const db = require('../config/db');
const { encrypt, decrypt } = require('../utils/encryption'); // Encryption utility with user-specific key

const router = express.Router();

const authenticateToken = require('../middlewares/authenticateToken'); // Authentication middleware

// Post credentials
router.post('/', authenticateToken, async (req, res) => {
    const { name, link, password } = req.body;
    const userId = req.user.id;

    try {
        // Encrypt the credentials with the user's specific key
        const encryptedName = await encrypt(name, userId);
        const encryptedLink = await encrypt(link, userId);
        const encryptedPassword = await encrypt(password, userId);

        // Insert the encrypted values into the database
        await db.query('INSERT INTO credentials (name, link, password, user_id) VALUES (?, ?, ?, ?)', [encryptedName, encryptedLink, encryptedPassword, userId]);
        res.status(201).send('Credentials added');
    } catch (error) {
        console.error('Error adding credentials:', error);
        res.status(500).send('Error adding credentials');
    }
});

// Get credentials
router.get('/', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try {
        // Retrieve the encrypted credentials for the user
        const [rows] = await db.query('SELECT * FROM credentials WHERE user_id = ?', [userId]);

        // Decrypt each row's credentials
        const decryptedRows = await Promise.all(rows.map(async (row) => ({
            id: row.id,
            name: await decrypt(row.name, userId),
            link: await decrypt(row.link, userId),
            password: await decrypt(row.password, userId)
        })));

        res.json(decryptedRows);
    } catch (error) {
        console.error('Error retrieving credentials:', error);
        res.status(500).send('Error retrieving credentials');
    }
});

// Edit (Update) credentials
router.put('/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { name, link, password } = req.body;
    const userId = req.user.id;

    try {
        // Encrypt the updated credentials with the user's specific key
        const encryptedName = await encrypt(name, userId);
        const encryptedLink = await encrypt(link, userId);
        const encryptedPassword = await encrypt(password, userId);

        // Update the credentials in the database
        const result = await db.query(
            'UPDATE credentials SET name = ?, link = ?, password = ? WHERE id = ? AND user_id = ?',
            [encryptedName, encryptedLink, encryptedPassword, id, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).send('Credential not found or unauthorized');
        }

        res.send('Credential updated successfully');
    } catch (error) {
        console.error('Error updating credentials:', error);
        res.status(500).send('Error updating credentials');
    }
});

// Delete credentials
router.delete('/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;

    try {
        // Delete the credential for the user
        const result = await db.query('DELETE FROM credentials WHERE id = ? AND user_id = ?', [id, userId]);

        if (result.affectedRows === 0) {
            return res.status(404).send('Credential not found or unauthorized');
        }

        res.send('Credential deleted successfully');
    } catch (error) {
        console.error('Error deleting credential:', error);
        res.status(500).send('Error deleting credential');
    }
});

module.exports = router;
