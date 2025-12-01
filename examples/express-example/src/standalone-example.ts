/**
 * Express.js standalone example application using passport-citizenid
 * 
 * This example demonstrates how to integrate Citizen iD authentication
 * into an Express.js application.
 * 
 * Prerequisites:
 *   - Set CITIZENID_CLIENT_ID environment variable
 *   - Set CITIZENID_CLIENT_SECRET environment variable (optional for public clients)
 *   - Set CALLBACK_URL environment variable (defaults to http://localhost:3000/auth/citizenid/callback)
 * 
 * Run with:
 *   npm run build && node dist/standalone-example.js
 *   or
 *   npm run dev:ts -- src/standalone-example.ts
 */

import express, { Request, Response, NextFunction } from 'express';
import session from 'express-session';
import passport from 'passport';
import { Strategy as CitizenIDStrategy, CitizenIDProfile, Scopes, PassportDoneCallback } from 'passport-citizenid';
import dotenv from 'dotenv';

dotenv.config();

// Load environment variables
const PORT = process.env.PORT || 3000;
const CITIZENID_CLIENT_ID = process.env.CITIZENID_CLIENT_ID;
const CITIZENID_CLIENT_SECRET = process.env.CITIZENID_CLIENT_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL || `http://localhost:${PORT}/auth/citizenid/callback`;

if (!CITIZENID_CLIENT_ID) {
  console.error('Error: CITIZENID_CLIENT_ID environment variable is required');
  process.exit(1);
}

const app = express();

// Configure session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-this-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Initialize Passport
app.use(passport.initialize() as any);
app.use(passport.session() as any);

// Configure Citizen iD Strategy
passport.use(new CitizenIDStrategy({
    clientID: CITIZENID_CLIENT_ID,
    clientSecret: CITIZENID_CLIENT_SECRET, // Optional for public clients with PKCE
    callbackURL: CALLBACK_URL,
    scope: [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL, Scopes.ROLES, Scopes.OFFLINE_ACCESS]
  },
  function(accessToken: string, refreshToken: string, profile: CitizenIDProfile, done: PassportDoneCallback<CitizenIDProfile>) {
    // In a real application, you would:
    // 1. Check if user exists in your database
    // 2. Create or update user record
    // 3. Store accessToken and refreshToken securely
    
    console.log('User authenticated:', profile.displayName);
    console.log('User ID:', profile.id);
    console.log('User roles:', profile.roles);
    console.log('Refresh token available:', !!refreshToken);
    
    // For this example, we'll just pass the profile
    // In production, you'd typically do:
    // User.findOrCreate({ citizenId: profile.id }, { 
    //   accessToken, 
    //   refreshToken,
    //   profile 
    // }, done);
    
    return done(null, profile);
  }
));

// Serialize user for session
passport.serializeUser((user: CitizenIDProfile, done) => {
  // In production, you'd typically serialize just the user ID
  done(null, user);
});

// Deserialize user from session
passport.deserializeUser((user: CitizenIDProfile, done) => {
  // In production, you'd fetch the user from your database
  done(null, user);
});

// Middleware to check if user is authenticated
function isAuthenticated(req: Request, res: Response, next: NextFunction) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

// Extend Express Request to include CitizenIDProfile
declare global {
  namespace Express {
    interface User extends CitizenIDProfile {}
  }
}

// Routes
app.get('/', (req: Request, res: Response) => {
  if (req.isAuthenticated() && req.user) {
    const user = req.user as CitizenIDProfile;
    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Citizen iD Authentication - Success</title>
          <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            .profile { background: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0; }
            .profile h2 { margin-top: 0; }
            .profile-item { margin: 10px 0; }
            .profile-item strong { display: inline-block; width: 150px; }
            .roles { display: flex; flex-wrap: wrap; gap: 5px; }
            .role { background: #007bff; color: white; padding: 5px 10px; border-radius: 3px; font-size: 0.9em; }
            .logout { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #dc3545; color: white; text-decoration: none; border-radius: 5px; }
            .logout:hover { background: #c82333; }
          </style>
        </head>
        <body>
          <h1>Welcome, ${user.displayName}!</h1>
          <div class="profile">
            <h2>Profile Information</h2>
            <div class="profile-item"><strong>User ID:</strong> ${user.id}</div>
            <div class="profile-item"><strong>Username:</strong> ${user.username}</div>
            <div class="profile-item"><strong>Display Name:</strong> ${user.displayName}</div>
            ${user.emails.length > 0 ? `<div class="profile-item"><strong>Email:</strong> ${user.emails[0].value}</div>` : ''}
            ${user.roles.length > 0 ? `
              <div class="profile-item">
                <strong>Roles:</strong>
                <div class="roles">
                  ${user.roles.map((role: string) => `<span class="role">${role}</span>`).join('')}
                </div>
              </div>
            ` : ''}
          </div>
          <a href="/logout" class="logout">Logout</a>
        </body>
      </html>
    `);
  } else {
    res.redirect('/login');
  }
});

app.get('/login', (req: Request, res: Response) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Citizen iD Authentication</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 600px; margin: 100px auto; padding: 20px; text-align: center; }
          .login-button { display: inline-block; padding: 15px 30px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; font-size: 1.2em; }
          .login-button:hover { background: #0056b3; }
        </style>
      </head>
      <body>
        <h1>Citizen iD Authentication Example</h1>
        <p>Click the button below to authenticate with Citizen iD</p>
        <a href="/auth/citizenid" class="login-button">Login with Citizen iD</a>
      </body>
    </html>
  `);
});

// Initiate authentication
app.get('/auth/citizenid',
  passport.authenticate('citizenid', {
    // Optional: Add custom authorization parameters
    // nonce: 'random-nonce-value',
    // prompt: 'login', // Force re-authentication
  })
);

// Handle callback
app.get('/auth/citizenid/callback',
  passport.authenticate('citizenid', { 
    failureRedirect: '/login',
    failureMessage: true
  }),
  (req: Request, res: Response) => {
    // Successful authentication
    res.redirect('/');
  }
);

// Logout route
app.get('/logout', (req: Request, res: Response) => {
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/');
  });
});

// Protected route example
app.get('/protected', isAuthenticated, (req: Request, res: Response) => {
  const user = req.user as CitizenIDProfile;
  res.json({
    message: 'This is a protected route',
    user: {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      roles: user.roles
    }
  });
});

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Error:', err);
  res.status(500).send('Internal Server Error');
});

// Start server
app.listen(PORT, () => {
  console.log(`\n🚀 Server running on http://localhost:${PORT}`);
  console.log(`\n📋 Configuration:`);
  console.log(`   Client ID: ${CITIZENID_CLIENT_ID}`);
  console.log(`   Callback URL: ${CALLBACK_URL}`);
  console.log(`   PKCE: Enabled (default)`);
  console.log(`\n🔗 Visit http://localhost:${PORT} to test authentication\n`);
});
