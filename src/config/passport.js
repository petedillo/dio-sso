const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { User } = require('../../models');
const config = require('./config');

// Serialize user into the session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from the session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findByPk(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

// Configure Google OAuth strategy
passport.use(new GoogleStrategy({
    clientID: config.google.clientId,
    clientSecret: config.google.clientSecret,
    callbackURL: config.google.callbackUrl,
    passReqToCallback: true
  },
  async (req, accessToken, refreshToken, profile, done) => {
    try {
      // Extract user data from Google profile
      const { id, displayName, emails, photos } = profile;
      const email = emails && emails[0] ? emails[0].value : null;
      const photo = photos && photos[0] ? photos[0].value : null;

      if (!email) {
        return done(null, false, { message: 'No email provided by Google' });
      }

      // Find user by Google ID or email
      let user = await User.findOne({
        where: {
          [Sequelize.Op.or]: [
            { googleId: id },
            { email: email.toLowerCase() }
          ]
        }
      });

      if (!user) {
        // User not found - don't create new users via Google SSO
        return done(null, false, { message: 'No account found with this email' });
      }

      // Update user with Google ID if not set
      if (!user.googleId) {
        user.googleId = id;
        await user.save();
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

module.exports = passport;
