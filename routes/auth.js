const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const checkIpAddress = require('../middlewares/checkIpAddress'); // Import the middleware

const router = express.Router();
const secret = 'goldenheart';  // Use a secure key management in production

const crypto = require('crypto');

// Register
router.post('/register', async (req, res) => {
    const { email, password } = req.body;
    var ipAddress = ''
    if(req.body.hasOwnProperty('ip')){
        ipAddress = req.body.ip;
    }else{
        res.status(500).send('Connot proceed without IP address');
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into the users table
        await db.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword]);

        // Retrieve user ID by querying the user by email
        const [userResult] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        const userId = userResult[0]?.id;

        if (!userId) {
            throw new Error('User ID not found');
        }

        // Insert IP address into the ip_address table
        await db.query('INSERT INTO ip_address (user_id, ip) VALUES (?, ?)', [userId, ipAddress]);

        // Generate a random key (32 characters hex)
        const randomKey = crypto.randomBytes(16).toString('hex'); // Generates 32 characters

        // Insert the generated key into the enkeys table
        await db.query('INSERT INTO enkeys (user_id, `key`) VALUES (?, ?)', [userId, randomKey]);

        res.status(201).send('User registered');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error registering user');
    }
});



// Login with IP Address Check
router.post('/login', checkIpAddress, async (req, res) => {
    const { email, password} = req.body;
    try {
        const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(400).send('User not found');
        
        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid credentials');
        
        const token = jwt.sign({ id: user.id }, secret, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).send('Error logging in');
    }
});

module.exports = router;
