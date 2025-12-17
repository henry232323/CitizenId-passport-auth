# passport-citizenid

[Passport](http://passportjs.org/) strategy for authenticating with [Citizen iD](https://citizenid.space/) using the OAuth 2.0 API with OpenID Connect.

This module lets you authenticate using Citizen iD in your Node.js applications. By plugging into Passport, Citizen iD authentication can be easily and unobtrusively integrated into any application or framework that supports [Connect](http://www.senchalabs.org/connect/)-style middleware, including [Express](http://expressjs.com/).

## Installation

```bash
npm install passport-citizenid
```

## Usage

### Configure Strategy

The Citizen iD authentication strategy authenticates users using a Citizen iD account and OAuth 2.0 tokens with OpenID Connect. The strategy requires a `verify` callback, which accepts these credentials and calls `done` providing a user, as well as `options` specifying a client ID, client secret, and callback URL.

```javascript
const { Strategy: CitizenIDStrategy, Scopes } = require('passport-citizenid');

passport.use(new CitizenIDStrategy({
    clientID: CITIZENID_CLIENT_ID,
    clientSecret: CITIZENID_CLIENT_SECRET, // Optional for public clients with PKCE
    callbackURL: "http://localhost:3000/auth/citizenid/callback",
    scope: [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL, Scopes.ROLES]
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({ citizenId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));
```

### Authenticate Requests

Use `passport.authenticate()`, specifying the `'citizenid'` strategy, to authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/) application:

```javascript
app.get('/auth/citizenid',
  passport.authenticate('citizenid'));

app.get('/auth/citizenid/callback', 
  passport.authenticate('citizenid', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });
```

## Configuration Options

### Getting Client Credentials

To use this strategy, you'll need to register an application with Citizen iD and obtain your client credentials. For detailed instructions on how to create and configure your OAuth2 client, see the [Citizen iD OAuth2 Documentation](https://docs.citizenid.space/integrator-guide/oauth2/).

### Required Options

- **clientID**: Your Citizen iD application's Client ID
- **callbackURL**: URL to which Citizen iD will redirect the user after granting authorization

### Optional Options

- **authority**: Base authority (e.g., `https://citizenid.space` or `https://dev.citizenid.space`). If provided, endpoints are derived automatically.
- **endpoints**: Explicit endpoints object to override derived values (authorizationURL, tokenURL, userInfoURL, revokeURL, discoveryURL).
- **clientSecret**: Your Citizen iD application's Client Secret (optional for public clients using PKCE)
- **scope**: Array of permission scopes to request
  - Default: `[Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL]`
  - Available scopes: Use `Scopes` constants (e.g., `Scopes.OPENID`, `Scopes.PROFILE`, `Scopes.EMAIL`, `Scopes.ROLES`, `Scopes.OFFLINE_ACCESS`, `Scopes.DISCORD_PROFILE`, etc.)
- **authorizationURL**: Authorization endpoint URL  
  - Default: `getEndpoints(Endpoints.PRODUCTION.AUTHORITY).AUTHORIZATION` (use `Endpoints.DEVELOPMENT.AUTHORITY` for dev)
- **tokenURL**: Token endpoint URL  
  - Default: `getEndpoints(Endpoints.PRODUCTION.AUTHORITY).TOKEN`
- **userInfoURL**: UserInfo endpoint URL  
  - Default: `getEndpoints(Endpoints.PRODUCTION.AUTHORITY).USERINFO`
- **pkce**: Enable PKCE (Proof Key for Code Exchange)
  - Default: `true` (recommended for security)
- **state**: Enable state parameter for CSRF protection
  - Default: `true`
- **passReqToCallback**: Pass the request to the verify callback
  - Default: `false`

## Examples

### Basic Express.js Application

```javascript
const express = require('express');
const passport = require('passport');
const { Strategy: CitizenIDStrategy, Scopes } = require('passport-citizenid');

const app = express();

// Configure Passport
passport.use(new CitizenIDStrategy({
    clientID: process.env.CITIZENID_CLIENT_ID,
    clientSecret: process.env.CITIZENID_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/citizenid/callback",
    scope: [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL]
  },
  function(accessToken, refreshToken, profile, done) {
    // In a real application, you would save the user to your database
    return done(null, profile);
  }
));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Middleware
app.use(require('express-session')({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`Hello ${req.user.displayName}! <a href="/logout">Logout</a>`);
  } else {
    res.send('<a href="/auth/citizenid">Login with Citizen iD</a>');
  }
});

app.get('/auth/citizenid',
  passport.authenticate('citizenid'));

app.get('/auth/citizenid/callback',
  passport.authenticate('citizenid', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/');
  });

app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

app.listen(3000, () => {
  console.log('Server listening on http://localhost:3000');
});
```

### Public Client with PKCE (No Client Secret)

For public clients (like single-page applications or mobile apps), you can omit the client secret and rely on PKCE:

```javascript
const { Strategy: CitizenIDStrategy, Scopes } = require('passport-citizenid');

passport.use(new CitizenIDStrategy({
    clientID: process.env.CITIZENID_CLIENT_ID,
    callbackURL: "http://localhost:3000/auth/citizenid/callback",
    pkce: true, // Enabled by default
    scope: [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL]
  },
  function(accessToken, refreshToken, profile, done) {
    return done(null, profile);
  }
));
```

### Request Offline Access (Refresh Token)

To receive a refresh token, include the `offline_access` scope:

```javascript
const { Strategy: CitizenIDStrategy, Scopes } = require('passport-citizenid');

passport.use(new CitizenIDStrategy({
    clientID: process.env.CITIZENID_CLIENT_ID,
    clientSecret: process.env.CITIZENID_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/citizenid/callback",
    scope: [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL, Scopes.ROLES, Scopes.OFFLINE_ACCESS]
  },
  function(accessToken, refreshToken, profile, done) {
    // refreshToken will be available here
    console.log('Refresh Token:', refreshToken);
    return done(null, profile);
  }
));
```

### Custom Authorization Parameters

You can pass custom parameters to the authorization request:

```javascript
app.get('/auth/citizenid',
  passport.authenticate('citizenid', {
    nonce: 'random-nonce-value',
    responseMode: 'form_post',
    prompt: 'login' // Force user to re-authenticate
  })
);
```

### TypeScript Usage

```typescript
import { Strategy as CitizenIDStrategy, CitizenIDProfile, CitizenIDStrategyOptions, Scopes, Endpoints } from 'passport-citizenid';
import passport from 'passport';

const options: CitizenIDStrategyOptions = {
  clientID: process.env.CITIZENID_CLIENT_ID!,
  clientSecret: process.env.CITIZENID_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/citizenid/callback",
  scope: [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL, Scopes.ROLES]
};

passport.use(new CitizenIDStrategy(options,
  (accessToken: string, refreshToken: string, profile: CitizenIDProfile, done: any) => {
    // Your user logic here
    return done(null, profile);
  }
));
```

### Using Constants

The package exports constants for scopes, endpoints, roles, and avatar claim keys:

```typescript
import { Scopes, Endpoints, Roles, AvatarClaimKeys, STANDARD_SCOPES, ALL_SCOPES, getEndpoints } from 'passport-citizenid';

// Use scope constants
passport.use(new CitizenIDStrategy({
  // ...
  scope: [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL, Scopes.ROLES, Scopes.OFFLINE_ACCESS]
}));

// Use predefined scope arrays
passport.use(new CitizenIDStrategy({
  // ...
  scope: STANDARD_SCOPES  // [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL]
}));

passport.use(new CitizenIDStrategy({
  // ...
  scope: ALL_SCOPES  // All available scopes including custom profile scopes
}));

// Use endpoint helpers for custom configuration
const authority = process.env.CITIZENID_AUTHORITY || Endpoints.DEVELOPMENT.AUTHORITY; // or PRODUCTION.AUTHORITY
const endpoints = getEndpoints(authority);
passport.use(new CitizenIDStrategy({
  // ...
  authorizationURL: process.env.CITIZENID_AUTHORIZATION_URL || endpoints.AUTHORIZATION,
  tokenURL: process.env.CITIZENID_TOKEN_URL || endpoints.TOKEN,
  userInfoURL: process.env.CITIZENID_USERINFO_URL || endpoints.USERINFO,
}));

// Access additional endpoints (for token revocation, OIDC discovery, etc.)
const prodEndpoints = getEndpoints(Endpoints.PRODUCTION.AUTHORITY);
console.log('Revoke endpoint:', prodEndpoints.REVOKE);
console.log('Discovery endpoint:', prodEndpoints.DISCOVERY);

// Check user roles using role constants
function verify(accessToken, refreshToken, profile, done) {
  const isIntegrator = profile.roles.includes(Roles.ACCOUNT_ROLE_INTEGRATOR);
  const isVerified = profile.roles.includes(Roles.STATUS_VERIFIED);
  const isBanned = profile.roles.includes(Roles.STATUS_BANNED);
  const isCitizen = profile.roles.includes(Roles.ACCOUNT_TYPE_CITIZEN);
  const isOrganization = profile.roles.includes(Roles.ACCOUNT_TYPE_ORGANIZATION);
  const isPartner = profile.roles.includes(Roles.ACCOUNT_ROLE_PARTNER);
  // ...
}

// Access typed custom claims directly on the profile (recommended)
// Use claim key constants for type-safe access
import { GoogleClaimKeys, TwitchClaimKeys, DiscordClaimKeys, RSIClaimKeys } from 'passport-citizenid';

if (profile.google) {
  const googleAccountId = profile.google[GoogleClaimKeys.ACCOUNT_ID];
  const googleEmail = profile.google[GoogleClaimKeys.EMAIL];
  const googleAvatar = profile.google[GoogleClaimKeys.AVATAR_URL];
}

if (profile.twitch) {
  const twitchAccountId = profile.twitch[TwitchClaimKeys.ACCOUNT_ID];
  const twitchUsername = profile.twitch[TwitchClaimKeys.USERNAME];
  const twitchAvatar = profile.twitch[TwitchClaimKeys.AVATAR_URL];
}

if (profile.discord) {
  const discordAccountId = profile.discord[DiscordClaimKeys.ACCOUNT_ID];
  const discordUsername = profile.discord[DiscordClaimKeys.USERNAME];
  const discordScopes = profile.discord[DiscordClaimKeys.SCOPES];
  const discordAvatar = profile.discord[DiscordClaimKeys.AVATAR_URL];
}

if (profile.rsi) {
  const rsiCitizenId = profile.rsi[RSIClaimKeys.CITIZEN_ID];
  const rsiSpectrumId = profile.rsi[RSIClaimKeys.SPECTRUM_ID];
  const rsiUsername = profile.rsi[RSIClaimKeys.USERNAME];
  const rsiEnlistedAt = profile.rsi[RSIClaimKeys.ENLISTED_AT];
  const rsiAvatar = profile.rsi[RSIClaimKeys.AVATAR_URL];
}

// Access avatar URLs from custom claims (alternative method using constants)
if (profile._customClaims) {
  const discordAvatar = profile._customClaims[AvatarClaimKeys.DISCORD];
  const rsiAvatar = profile._customClaims[AvatarClaimKeys.RSI];
  const googleAvatar = profile._customClaims[AvatarClaimKeys.GOOGLE];
  const twitchAvatar = profile._customClaims[AvatarClaimKeys.TWITCH];
  // ...
}

// Helper constants for constructing custom claim keys
import { CUSTOM_CLAIM_PREFIX, AVATAR_URL_SUFFIX } from 'passport-citizenid';
// Custom claim keys follow the pattern: CUSTOM_CLAIM_PREFIX + provider + AVATAR_URL_SUFFIX
// Example: CUSTOM_CLAIM_PREFIX + 'discord' + AVATAR_URL_SUFFIX = 'urn:user:discord:avatar:url'
```

Available scope constants:
- `Scopes.OPENID` - Required for OpenID Connect
- `Scopes.PROFILE` - Basic profile information
- `Scopes.EMAIL` - Email address
- `Scopes.ROLES` - User roles
- `Scopes.OFFLINE_ACCESS` - Refresh token
- `Scopes.GOOGLE_PROFILE` - Google account information
- `Scopes.TWITCH_PROFILE` - Twitch account information
- `Scopes.DISCORD_PROFILE` - Discord account information
- `Scopes.RSI_PROFILE` - RSI (Roberts Space Industries) account information

Available role constants:
- `Roles.STATUS_VERIFIED` - Account has been linked with RSI and verified
- `Roles.STATUS_BANNED` - Account has been suspended
- `Roles.ACCOUNT_TYPE_ORGANIZATION` - Registered organization account
- `Roles.ACCOUNT_TYPE_CITIZEN` - Individual user account
- `Roles.ACCOUNT_ROLE_PARTNER` - Trusted external partner organization
- `Roles.ACCOUNT_ROLE_INTEGRATOR` - Entity integrating with the Citizen iD platform
- `Roles.INTERNAL_SYSTEM` - System-level operations (internal use only)
- `Roles.INTERNAL_SUPER_ADMIN` - Highest administrative privileges (internal use only)
- `Roles.INTERNAL_ADMIN` - Standard administrative privileges (internal use only)
- `Roles.INTERNAL_MODERATOR` - Content moderation privileges (internal use only)

**Note:** Internal roles are reserved for Citizen iD staff and should not be used in your applications.

### Accessing User Roles

The Citizen iD profile includes user roles when the `roles` scope is requested:

```javascript
const { Scopes, Roles } = require('passport-citizenid');

passport.use(new CitizenIDStrategy({
    clientID: process.env.CITIZENID_CLIENT_ID,
    clientSecret: process.env.CITIZENID_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/citizenid/callback",
    scope: [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL, Scopes.ROLES]
  },
  function(accessToken, refreshToken, profile, done) {
    console.log('User roles:', profile.roles);
    
    // Check if user has a specific role using constants
    const isIntegrator = profile.roles.includes(Roles.ACCOUNT_ROLE_INTEGRATOR);
    const isVerified = profile.roles.includes(Roles.STATUS_VERIFIED);
    const isCitizen = profile.roles.includes(Roles.ACCOUNT_TYPE_CITIZEN);
    
    return done(null, profile);
  }
));
```

## Profile Structure

The user profile returned by Citizen iD contains the following fields:

```javascript
{
  provider: 'citizenid',
  id: '0199a109-3662-7f83-b155-5bc53db7bf26',
  username: 'thekronny',
  displayName: 'thekronny',
  emails: [
    {
      value: '...',
      verified: false
    }
  ],
  roles: [
    'CitizenId.AccountType.Citizen',
    'CitizenId.Integrator'
  ],
  photos: [  // Avatar URLs from custom profile scopes (e.g., discord.profile, rsi.profile)
    {
      value: 'https://cdn.discordapp.com/avatars/...'  // From urn:user:discord:avatar:url
    },
    {
      value: 'https://robertsspaceindustries.com/...'  // From urn:user:rsi:avatar:url
    }
  ],
  authorizationId: '0199a3df-6c1a-70e8-acf8-db72fd00a0ff',
  _customClaims: {  // All custom claims (urn:user:*)
    'urn:user:discord:avatar:url': 'https://...',
    'urn:user:rsi:avatar:url': 'https://...',
    // ... other custom claims
  },
  _raw: '...',
  _json: {
    sub: '0199a109-3662-7f83-b155-5bc53db7bf26',
    name: 'thekronny',
    preferred_username: 'thekronny',
    email: '...',
    role: ['CitizenId.AccountType.Citizen', 'CitizenId.Integrator'],
    // ... other OIDC claims
  }
}
```

**Note:** Avatar URLs are automatically extracted from custom profile claims (e.g., `urn:user:discord:avatar:url`, `urn:user:rsi:avatar:url`) and added to the `photos` array when the corresponding profile scopes are requested.

## OAuth2 Flows Supported

This strategy supports the following OAuth2 flows:

- **Authorization Code Flow** (with PKCE support)
- **Refresh Token Flow** (when `offline_access` scope is requested)

For more information about Citizen iD's OAuth2 implementation, see the [Citizen iD OAuth2 Documentation](https://docs.citizenid.space/integrator-guide/oauth2/flows-grants.html).

## Security Considerations

1. **PKCE**: This strategy enables PKCE by default for enhanced security. It's especially important for public clients.

2. **State Parameter**: The state parameter is enabled by default to protect against CSRF attacks.

3. **HTTPS**: Always use HTTPS in production for your callback URLs.

4. **Client Secret**: Keep your client secret secure. Never expose it in client-side code.

5. **Token Storage**: Store refresh tokens securely. Consider encrypting them in your database.

## Testing

You can test the authorization flow using the [OAuth 2.0 Debugger](https://oauthdebugger.com/debug):

1. Set Authorize URI to: `getEndpoints(Endpoints.PRODUCTION.AUTHORITY).AUTHORIZATION` (or use `Endpoints.DEVELOPMENT.AUTHORITY` for dev)
2. Use your Client ID
3. Set your callback URL
4. Select the scopes you want to test (use `Scopes` constants)

## License

[MIT](LICENSE)

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/ArkanisCorporation/CitizenId-passport-auth).

## Related Resources

- [Citizen iD Documentation](https://docs.citizenid.space/)
- [Passport.js Documentation](http://www.passportjs.org/)
- [OAuth 2.0 Specification](https://oauth.net/2/)
- [OpenID Connect Specification](https://openid.net/connect/)
