const jwt = require('jsonwebtoken');
const config = require('../config/config');
const User = require('../../models/User');

/**
 * Authentication middleware that checks for a valid JWT token
 * Supports tokens from:
 * 1. Authorization header (Bearer token)
 * 2. Cookie (token=xxx)
 */
const authMiddleware = async (req, res, next) => {
  try {
    // Get token from Authorization header or cookie
    let token;
    
    // 1. Check Authorization header
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    } 
    // 2. Check cookies
    else if (req.cookies?.['dio-auth-token']) {
      token = req.cookies['dio-auth-token'];
    }
    
    if (!token) {
      return res.status(401).json({ 
        error: 'Authentication required',
        code: 'UNAUTHORIZED'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, config.jwtSecret);
    
    // Get user from database
    const user = await User.findByPk(decoded.id, {
      attributes: { 
        exclude: ['passwordHash', 'googleId'] 
      }
    });
    
    if (!user) {
      return res.status(401).json({ 
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    // Attach user to request object
    req.user = user.get({ plain: true });
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        error: 'Invalid token',
        code: 'INVALID_TOKEN'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Token expired', 
        code: 'TOKEN_EXPIRED'
      });
    }
    
    // For API requests, return JSON response
    if (req.path.startsWith('/api/')) {
      return res.status(500).json({ 
        error: 'Authentication failed',
        code: 'AUTH_FAILED'
      });
    }
    
    // For web routes, redirect to login
    res.redirect('/login?error=auth_failed');
  }
};

/**
 * Middleware to check if user is authenticated (for API routes)
 * Returns 401 if not authenticated
 */
authMiddleware.apiAuth = authMiddleware; // Alias for backward compatibility

/**
 * Middleware to check if user is authenticated (for web routes)
 * Redirects to login page if not authenticated
 */
authMiddleware.webAuth = (req, res, next) => {
  const isApiRoute = req.path.startsWith('/api/');
  const originalJson = res.json;
  
  // Override res.json to handle redirects for non-API routes
  if (!isApiRoute) {
    res.json = (data) => {
      if (data?.error && data.error === 'Authentication required') {
        return res.redirect('/login');
      }
      return originalJson.call(res, data);
    };
  }
  
  authMiddleware(req, res, (err) => {
    if (err) return next(err);
    
    // For non-API routes, continue to next middleware if authenticated
    if (!isApiRoute) {
      return next();
    }
    
    // For API routes, continue with the original auth behavior
    next();
  });
};

module.exports = authMiddleware;
