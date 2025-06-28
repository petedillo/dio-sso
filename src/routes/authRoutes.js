const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const passport = require('passport');
const config = require('../config/config');
const User = require('../../models/User');
const authMiddleware = require('../middleware/authMiddleware');
const { Op } = require('sequelize');
const { validateRedirectUri, getSafeRedirect } = require('../utils/redirectValidator');

// Generate JWT token
const generateToken = (user) => {
  return jwt.sign(
    { id: user.id, email: user.email },
    config.jwtSecret,
    { expiresIn: '24h' }
  );
};

// Set JWT token as HTTP-only cookie
const setTokenCookie = (res, token) => {
  res.cookie('dio-auth-token', token, {
    domain: config.cookie.domain,
    secure: config.cookie.secure,
    httpOnly: config.cookie.httpOnly,
    sameSite: config.cookie.sameSite,
    maxAge: config.cookie.maxAge
  });
};

// Google OAuth routes
router.get('/google', (req, res, next) => {
  try {
    // Get the redirect URL from query params
    const requestedRedirect = req.query.redirect_uri;
    
    // Validate the redirect URI
    const { isValid, error } = validateRedirectUri(requestedRedirect);
    if (requestedRedirect && !isValid) {
      console.warn(`Invalid redirect URI attempt: ${requestedRedirect} - ${error}`);
      return res.status(400).json({ error: 'Invalid redirect URI' });
    }
    
    // Use the validated redirect or null (will be handled in the callback)
    const redirectTo = isValid ? requestedRedirect : null;
    
    // Store the redirect URL in the session
    req.session.redirectTo = redirectTo;
    
    // Initialize the Google OAuth flow with state parameter
    const state = Buffer.from(JSON.stringify({ 
      redirect_uri: redirectTo,
      // Add any additional state you need to pass through
      timestamp: Date.now()
    })).toString('base64');
    
    const authenticator = passport.authenticate('google', { 
      scope: ['profile', 'email'],
      session: false,
      state: state
    });
    
    authenticator(req, res, next);
  } catch (error) {
    console.error('Error in Google OAuth initiation:', error);
    next(error);
  }
});

router.get('/google/callback', (req, res, next) => {
  // Custom callback to handle redirect validation
  const authenticate = passport.authenticate('google', {
    session: false,
    failureRedirect: '/?error=auth_failed'
  }, async (err, user, info) => {
    try {
      if (err || !user) {
        console.error('Google OAuth error:', err || 'No user returned');
        return res.redirect('/?error=auth_failed');
      }

      // Get redirect URI from state or session
      let redirectUri = '/';
      try {
        if (req.query.state) {
          const state = JSON.parse(Buffer.from(req.query.state, 'base64').toString());
          if (state.redirect_uri) {
            const { isValid } = validateRedirectUri(state.redirect_uri);
            if (isValid) {
              redirectUri = getSafeRedirect(state.redirect_uri);
            }
          }
        }
      } catch (e) {
        console.error('Error parsing state:', e);
      }

      // Generate token
      const token = generateToken(user);
      
      // Set the token in an HTTP-only cookie
      setTokenCookie(res, token);
      
      // If this is an API request, return JSON
      if (req.accepts('json')) {
        return res.json({ token });
      }
      
      // Otherwise, redirect with the token in the URL if needed
      const url = new URL(redirectUri);
      url.searchParams.set('token', token);
      
      return res.redirect(url.toString());
    } catch (error) {
      console.error('Error in Google OAuth callback:', error);
      return res.redirect(`/?error=auth_error`);
    }
  });
  
  authenticate(req, res, next);
});

// Local login route
router.post('/login', async (req, res) => {
  try {
    const { email, password, redirect_uri } = req.body;
    
    // Validate redirect URI if provided
    if (redirect_uri) {
      const { isValid, error } = validateRedirectUri(redirect_uri);
      if (!isValid) {
        console.warn(`Invalid redirect URI attempt: ${redirect_uri} - ${error}`);
        return res.status(400).json({ error: 'Invalid redirect URI' });
      }
    }
    
    // Find user by email
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Verify password
    const isValidPassword = await user.validPassword(password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate token
    const token = generateToken(user);
    
    // Set the token in an HTTP-only cookie
    setTokenCookie(res, token);
    
    // If this is an API request, return JSON
    if (req.accepts('json')) {
      return res.json({ token });
    }
    
    // Otherwise, redirect if a valid URI was provided
    if (redirect_uri) {
      const safeRedirect = getSafeRedirect(redirect_uri, '/');
      const url = new URL(safeRedirect);
      url.searchParams.set('token', token);
      return res.redirect(url.toString());
    }
    
    // Default redirect if no valid URI provided
    return res.redirect('/');
    
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'An error occurred during login' });
  }
});

// Verify token (for subdomains)
router.get('/verify', authMiddleware, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// Logout
router.post('/logout', (req, res) => {
  res.clearCookie('dio-auth-token', {
    domain: config.cookie.domain,
    path: '/',
    httpOnly: true,
    secure: config.cookie.secure
  });
  res.json({ message: 'Logged out successfully' });
});

// Register a new user
router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  try {
    const user = await User.create({ 
      username, 
      passwordHash: password
    });
    
    res.status(201).json({ 
      id: user.id, 
      username: user.username 
    });
  } catch (err) {
    if (err.name === 'SequelizeUniqueConstraintError') {
      return res.status(409).json({ error: 'Username already exists' });
    }
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login user
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const match = await user.validatePassword(password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken(user);
    setTokenCookie(res, token);
    
    res.json({ 
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        displayName: user.displayName,
        avatar: user.avatar
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: { exclude: ['passwordHash', 'googleId'] }
    });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ 
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        displayName: user.display_name,
        avatar: user.avatar,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      }
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

module.exports = router;
