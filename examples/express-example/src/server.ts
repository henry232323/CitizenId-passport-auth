import express, { Request, Response, NextFunction } from 'express';
import passport from 'passport';
import session from 'express-session';
import { 
  Strategy as CitizenIDStrategy, 
  CitizenIDProfile, 
  Scopes, 
  Endpoints, 
  getEndpoints, 
  PassportDoneCallback, 
  STANDARD_SCOPES, 
  ALL_SCOPES, 
  Roles,
  GoogleClaimKeys,
  TwitchClaimKeys,
  DiscordClaimKeys,
  RSIClaimKeys
} from 'passport-citizenid';
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
// Determine the authority (dev or prod) and get endpoints from env (with helper)
const authority = process.env.CITIZENID_AUTHORITY || Endpoints.PRODUCTION.AUTHORITY;
const endpoints = getEndpoints(authority);
console.log('[Example] CitizenID endpoints:', {
  authority,
  authorizationURL: process.env.CITIZENID_AUTHORIZATION_URL || endpoints.AUTHORIZATION,
  tokenURL: process.env.CITIZENID_TOKEN_URL || endpoints.TOKEN,
  userInfoURL: process.env.CITIZENID_USERINFO_URL || endpoints.USERINFO,
});
// Note: Additional endpoints available:
// - endpoints.REVOKE: Token revocation endpoint
// - endpoints.DISCOVERY: OpenID Connect discovery endpoint (.well-known/openid-configuration)

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
    // scope: [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL, Scopes.ROLES, Scopes.OFFLINE_ACCESS, Scopes.DISCORD_PROFILE, Scopes.RSI_PROFILE, Scopes.GOOGLE_PROFILE, Scopes.TWITCH_PROFILE]
    // Alternative: Use predefined scope arrays:
    // scope: STANDARD_SCOPES  // [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL]
    // scope: ALL_SCOPES  // All available scopes
  },
  function verify(accessToken: string, refreshToken: string, profile: CitizenIDProfile, done: PassportDoneCallback<CitizenIDProfile>) {
    // In this example, the user's Citizen iD profile is returned to
    // represent the logged-in user. In a typical application, you would want
    // to associate the Citizen iD account with a user record in your database,
    // and return that user instead.
    
    console.log('Access Token:', accessToken);
    console.log('Refresh Token:', refreshToken);
    console.log('Profile:', JSON.stringify(profile, null, 2));
    
    // Typed custom claims are available directly on the profile when corresponding scopes are requested
    // Use the claim key constants for type-safe access
    if (profile.google) {
      console.log('Google Profile:', {
        accountId: profile.google[GoogleClaimKeys.ACCOUNT_ID],
        name: profile.google[GoogleClaimKeys.NAME],
        email: profile.google[GoogleClaimKeys.EMAIL],
        avatarUrl: profile.google[GoogleClaimKeys.AVATAR_URL],
      });
    }
    
    if (profile.twitch) {
      console.log('Twitch Profile:', {
        accountId: profile.twitch[TwitchClaimKeys.ACCOUNT_ID],
        username: profile.twitch[TwitchClaimKeys.USERNAME],
        email: profile.twitch[TwitchClaimKeys.EMAIL],
        avatarUrl: profile.twitch[TwitchClaimKeys.AVATAR_URL],
      });
    }
    
    if (profile.discord) {
      console.log('Discord Profile:', {
        accountId: profile.discord[DiscordClaimKeys.ACCOUNT_ID],
        username: profile.discord[DiscordClaimKeys.USERNAME],
        scopes: profile.discord[DiscordClaimKeys.SCOPES],
        avatarUrl: profile.discord[DiscordClaimKeys.AVATAR_URL],
      });
    }
    
    if (profile.rsi) {
      console.log('RSI Profile:', {
        citizenId: profile.rsi[RSIClaimKeys.CITIZEN_ID],
        spectrumId: profile.rsi[RSIClaimKeys.SPECTRUM_ID],
        username: profile.rsi[RSIClaimKeys.USERNAME],
        enlistedAt: profile.rsi[RSIClaimKeys.ENLISTED_AT],
        avatarUrl: profile.rsi[RSIClaimKeys.AVATAR_URL],
      });
    }
    
    // All custom claims (from scopes like discord.profile, rsi.profile, etc.) are also available in profile._customClaims for backward compatibility
    if (profile._customClaims) {
      console.log('All Custom Claims:', JSON.stringify(profile._customClaims, null, 2));
    }
    
    // Example: Check user roles using role constants
    const isIntegrator = profile.roles.includes(Roles.ACCOUNT_ROLE_INTEGRATOR);
    const isVerified = profile.roles.includes(Roles.STATUS_VERIFIED);
    const isCitizen = profile.roles.includes(Roles.ACCOUNT_TYPE_CITIZEN);
    const isBanned = profile.roles.includes(Roles.STATUS_BANNED);
    const isOrganization = profile.roles.includes(Roles.ACCOUNT_TYPE_ORGANIZATION);
    const isPartner = profile.roles.includes(Roles.ACCOUNT_ROLE_PARTNER);
    
    console.log('Role checks:', { isIntegrator, isVerified, isCitizen, isBanned, isOrganization, isPartner });
    
    // Store tokens with the user profile for later use
    // Extend profile with tokens for this example (in production, store tokens separately)
    const userWithTokens = {
      ...profile,
      accessToken,
      refreshToken
    };
    
    return done(null, userWithTokens);
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
passport.serializeUser((user: CitizenIDProfile, done) => {
  done(null, user);
});

passport.deserializeUser((user: CitizenIDProfile, done) => {
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
  (req: Request, res: Response, next: NextFunction) => {
    passport.authenticate('citizenid', { 
      failureRedirect: '/login',
      failureMessage: true,
      session: true,
      failWithError: true,
    }, (err: any, user: any, info: any) => {
      console.log('[Example] CitizenID callback:', { hasErr: !!err, hasUser: !!user, info });
      if (err) {
        console.error('[Example] Auth error:', err);
        return next(err);
      }
      if (!user) {
        console.error('[Example] No user returned from strategy');
        return res.redirect('/login');
      }
      req.logIn(user, (loginErr) => {
        if (loginErr) {
          console.error('[Example] login error:', loginErr);
          return next(loginErr);
        }
        return res.redirect('/');
      });
    })(req, res, next);
  });

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
