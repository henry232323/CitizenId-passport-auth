import express, { Request, Response, NextFunction } from 'express';
import passport from 'passport';
import session from 'express-session';
import { Strategy as CitizenIDStrategy, CitizenIDProfile, Scopes, Endpoints, getEndpoints } from 'passport-citizenid';
import dotenv from 'dotenv';

// Extend Express Request to include CitizenIDProfile
declare global {
  namespace Express {
    interface User extends CitizenIDProfile {}
  }
}

dotenv.config();

const app = express();

// ============================================================================
// PASSPORT CONFIGURATION
// ============================================================================

/**
 * Configure the Citizen iD strategy for use by Passport.
 * 
 * OAuth 2.0-based strategies require a `verify` function which receives the
 * credential (`accessToken`) for accessing the Citizen iD API on the user's
 * behalf, along with the user's profile. The function must invoke `done`
 * with a user object, which will be set at `req.user` in route handlers after
 * authentication.
 */
// Determine the authority (dev or prod) and get endpoints
const authority = process.env.CITIZENID_AUTHORITY || Endpoints.PRODUCTION.AUTHORITY;
const endpoints = getEndpoints(authority);

passport.use(new CitizenIDStrategy({
    clientID: process.env.CITIZENID_CLIENT_ID!,
    clientSecret: process.env.CITIZENID_CLIENT_SECRET,
    callbackURL: process.env.CITIZENID_CALLBACK_URL || "http://localhost:3000/auth/citizenid/callback",
    authorizationURL: endpoints.AUTHORIZATION,
    tokenURL: endpoints.TOKEN,
    userInfoURL: endpoints.USERINFO,
    // Note: 'openid' scope is automatically added if missing (required for OIDC)
    // Using scope constants for type safety
    scope: [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL, Scopes.ROLES, Scopes.OFFLINE_ACCESS]
    // Example with custom profile scopes:
    // scope: [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL, Scopes.ROLES, Scopes.OFFLINE_ACCESS, Scopes.DISCORD_PROFILE, Scopes.RSI_PROFILE]
  },
  function verify(accessToken: string, refreshToken: string, profile: CitizenIDProfile, done: (error: any, user?: any) => void) {
    // In this example, the user's Citizen iD profile is returned to
    // represent the logged-in user. In a typical application, you would want
    // to associate the Citizen iD account with a user record in your database,
    // and return that user instead.
    
    console.log('Access Token:', accessToken);
    console.log('Refresh Token:', refreshToken);
    console.log('Profile:', JSON.stringify(profile, null, 2));
    
    // Custom claims (from scopes like discord.profile, rsi.profile, etc.) are available in profile._customClaims
    if (profile._customClaims) {
      console.log('Custom Claims:', JSON.stringify(profile._customClaims, null, 2));
    }
    
    // Store tokens with the user profile for later use
    (profile as any).accessToken = accessToken;
    (profile as any).refreshToken = refreshToken;
    
    return done(null, profile);
  }
));

/**
 * Configure Passport authenticated session persistence.
 * 
 * In order to restore authentication state across HTTP requests, Passport needs
 * to serialize users into and deserialize users out of the session. In a typical
 * application, this will be as simple as storing the user ID when serializing, and
 * finding the user by ID when deserializing.
 * 
 * However, since this example does not have a database, the complete profile is
 * serialized and deserialized.
 */
passport.serializeUser((user: any, done) => {
  done(null, user);
});

passport.deserializeUser((user: any, done) => {
  done(null, user);
});

// ============================================================================
// MIDDLEWARE
// ============================================================================

// View engine setup
import path from 'path';
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));

// Parse URL-encoded bodies (for form POST)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret-change-this-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Initialize Passport and restore authentication state from session
app.use(passport.initialize() as any);
app.use(passport.session() as any);

// ============================================================================
// ROUTES
// ============================================================================

/**
 * Home page
 */
app.get('/', (req: Request, res: Response) => {
  res.render('home', { user: req.user });
});

/**
 * Login page
 */
app.get('/login', (req: Request, res: Response) => {
  res.render('login');
});

/**
 * Initiate OAuth 2.0 authorization code flow with Citizen iD.
 * 
 * This route will redirect the user to Citizen iD where they will authenticate
 * and authorize this application to access their information.
 */
app.get('/auth/citizenid', passport.authenticate('citizenid'));

/**
 * OAuth 2.0 callback endpoint.
 * 
 * Citizen iD will redirect the user to this URL after they complete the
 * authorization process. The authorization code is included in the query string
 * and will be exchanged for an access token.
 */
app.get('/auth/citizenid/callback',
  passport.authenticate('citizenid', { 
    failureRedirect: '/login',
    failureMessage: true
  }),
  (req: Request, res: Response) => {
    // Successful authentication, redirect home
    res.redirect('/');
  }
);

/**
 * Profile page - requires authentication
 */
app.get('/profile', ensureAuthenticated, (req: Request, res: Response) => {
  res.render('profile', { user: req.user });
});

/**
 * Logout
 */
app.get('/logout', (req: Request, res: Response, next: NextFunction) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect('/');
  });
});

// ============================================================================
// MIDDLEWARE HELPERS
// ============================================================================

/**
 * Middleware to ensure user is authenticated.
 * If not authenticated, redirect to login page.
 */
function ensureAuthenticated(req: Request, res: Response, next: NextFunction) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).render('error', {
    message: 'Page not found',
    error: { status: 404 }
  });
});

// Error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Error:', err);
  res.status((err as any).status || 500).render('error', {
    message: err.message || 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err : {}
  });
});

// ============================================================================
// START SERVER
// ============================================================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   Citizen iD Passport Example Server                              ║
║                                                                   ║
║   Server is running on http://localhost:${PORT}                      ║
║                                                                   ║
║   Routes:                                                         ║
║   - GET  /                   Home page                            ║
║   - GET  /login              Login page                           ║
║   - GET  /auth/citizenid     Initiate OAuth flow                  ║
║   - GET  /profile            User profile (requires auth)         ║
║   - GET  /logout             Logout                               ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
  `);
  
  if (!process.env.CITIZENID_CLIENT_ID) {
    console.warn('\n⚠️  WARNING: CITIZENID_CLIENT_ID is not set in .env file');
  }
  
  if (!process.env.CITIZENID_CLIENT_SECRET) {
    console.warn('⚠️  WARNING: CITIZENID_CLIENT_SECRET is not set in .env file');
  }
  
  const authority = process.env.CITIZENID_AUTHORITY || Endpoints.PRODUCTION.AUTHORITY;
  console.log(`\n📡 Using Citizen iD Authority: ${authority}`);
  console.log('   (Set CITIZENID_AUTHORITY in .env to switch between dev/prod)\n');
  
  console.log('Make sure to configure your .env file with your Citizen iD credentials.\n');
});
