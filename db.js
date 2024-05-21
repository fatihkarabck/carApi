const mysql = require('mysql2');

const pool = mysql.createPool({
  host: '159.65.53.223',
  user: 'root',
  password: '883..Fatih',
  database: 'car_database'
});

module.exports = pool.promise();
