const crypto = require('crypto');
const algorithm = 'aes-256-cbc';
const db = require('../config/db'); // Assuming db is set up to handle your database queries

async function getUserKey(userId) {
    // Fetch the encryption key for the user from the `enkeys` table
    const [result] = await db.query('SELECT `key` FROM enkeys WHERE user_id = ?', [userId]);
    if (!result || !result[0]) {
        throw new Error('Encryption key not found for user');
    }
    return Buffer.from(result[0].key, 'utf8'); // Convert the key from the database to a buffer
}

async function encrypt(text, userId) {
    try {
        // Fetch the user's encryption key
        const key = await getUserKey(userId);

        const iv = crypto.randomBytes(16);
        let cipher = crypto.createCipheriv(algorithm, key, iv);
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        return iv.toString('hex') + ':' + encrypted.toString('hex');
    } catch (error) {
        console.error('Encryption error:', error);
        throw error;
    }
}

async function decrypt(text, userId) {
    try {
        // Fetch the user's encryption key
        const key = await getUserKey(userId);

        let textParts = text.split(':');
        let iv = Buffer.from(textParts.shift(), 'hex');
        let encryptedText = Buffer.from(textParts.join(':'), 'hex');
        let decipher = crypto.createDecipheriv(algorithm, key, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return decrypted.toString();
    } catch (error) {
        console.error('Decryption error:', error);
        throw error;
    }
}

module.exports = { encrypt, decrypt };
