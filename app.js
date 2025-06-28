const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const path = require('path');
const config = require('./src/config/config');
const { sequelize, testConnection } = require('./src/config/database');
const authRoutes = require('./src/routes/authRoutes');

// Import configurations and middleware
require('./src/config/passport');
const authMiddleware = require('./src/middleware/authMiddleware');

const app = express();

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests from all petedillo.com subdomains, auth.petedillo.com, and localhost for development
    const allowedOrigins = [
      /^https?:\/\/([a-z0-9]+\.)?petedillo\.com$/, // All subdomains of petedillo.com
      /^https?:\/\/auth\.petedillo\.com$/, // Explicitly allow auth.petedillo.com
      /^http:\/\/localhost(:\d+)?$/ // Localhost with any port
    ];
    
    if (!origin || allowedOrigins.some(regex => regex.test(origin))) {
      callback(null, true);
    } else {
      console.warn('CORS blocked request from origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Allow cookies to be sent with requests
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: config.session.secret,
  resave: config.session.resave,
  saveUninitialized: config.session.saveUninitialized,
  cookie: {
    ...config.cookie,
    path: '/',
    httpOnly: true
  }
}));

// Initialize Passport and session
app.use(passport.initialize());
app.use(passport.session());

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve login page at root
app.get(['/', '/login'], (req, res) => {
  // If already authenticated, redirect to the service that initiated the login
  if (req.cookies.token) {
    const redirectUrl = req.query.redirect_uri || process.env.FRONTEND_URL || 'http://localhost:3000';
    return res.redirect(redirectUrl);
  }
  
  // If there's a redirect_uri in the query, pass it to the login page
  if (req.query.redirect_uri) {
    return res.redirect(`/login?redirect_uri=${encodeURIComponent(req.query.redirect_uri)}`);
  }
  
  // Otherwise, show the login page
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Routes
app.use('/api/auth', authRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.stack);
  
  // Handle CORS errors
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'Not allowed by CORS' });
  }
  
  // Handle JWT errors
  if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  
  // Handle Sequelize validation errors
  if (err.name === 'SequelizeValidationError' || err.name === 'SequelizeUniqueConstraintError') {
    const errors = err.errors.map(e => ({
      field: e.path,
      message: e.message
    }));
    return res.status(400).json({ 
      error: 'Validation failed',
      details: errors 
    });
  }
  
  // Default error handler
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

const PORT = config.port || 4444;

// Initialize database and start server
const startServer = async () => {
    try {
        // Test database connection
        await testConnection();
        
        // Sync all models with database
        await sequelize.sync({ alter: true });
        console.log('Database synced');
        
        // Start the server
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
};

startServer();
