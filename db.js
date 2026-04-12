const sql = require('mssql');

const config = {
    user: 'sa',
    password: 'joanemmanuel08',
    server: 'localhost',
    database: 'imc_plus',
    options: {
        encrypt: false,
        trustServerCertificate: true
    }
};

const poolPromise = new sql.ConnectionPool(config)
    .connect()
    .then(pool => {
        console.log(' ¡CONEXIÓN EXITOSA!');
        return pool;
    })
    .catch(err => {
        console.log('ERROR DE CONEXIÓN:', err.message);
    });

module.exports = { sql, poolPromise };