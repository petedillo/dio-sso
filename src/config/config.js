require('dotenv').config();

// Allowed redirect domains (include all domains that should be able to use this auth service)
const ALLOWED_REDIRECT_DOMAINS = [
    'localhost:3000',
    'petedillo.com',
    'app.petedillo.com'
    // Add other allowed domains here in production
];

const config = {
    port: process.env.PORT || 4444,
    jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
    allowedRedirectDomains: process.env.ALLOWED_REDIRECT_DOMAINS 
        ? process.env.ALLOWED_REDIRECT_DOMAINS.split(',') 
        : ALLOWED_REDIRECT_DOMAINS,
    cookie: {
        domain: process.env.COOKIE_DOMAIN || 'localhost',
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    },
    google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackUrl: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:4444/api/auth/google/callback',
        scope: ['profile', 'email']
    },
    session: {
        secret: process.env.SESSION_SECRET || 'your-session-secret',
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: process.env.NODE_ENV === 'production',
            httpOnly: true,
            sameSite: 'lax',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        }
    },
    db: {
        username: process.env.DB_USERNAME || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'dio_auth',
        host: process.env.DB_HOST || 'localhost',
        dialect: process.env.DB_DIALECT || 'postgres'
    }
};

// Validate required environment variables
const requiredVars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'];
const missingVars = requiredVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.error('Missing required environment variables:', missingVars.join(', '));
    if (process.env.NODE_ENV === 'production') {
        process.exit(1);
    }
}

module.exports = config;
