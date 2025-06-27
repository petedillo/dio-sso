require('dotenv').config();

const config = {
    port: process.env.PORT || 4444,
    jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
    db: {
        username: process.env.DB_USERNAME || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'dio_auth',
        host: process.env.DB_HOST || 'localhost',
        dialect: process.env.DB_DIALECT || 'postgres'
    }
};

module.exports = config;
