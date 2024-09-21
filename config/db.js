const mysql = require('mysql2');

const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'crud'
});

// const pool = mysql.createPool({
//     host: '34.226.136.144',
//     user: 'rahul',
//     password: 'taj123W',
//     database: 'crud'
// });

const promisePool = pool.promise();

module.exports = promisePool;
