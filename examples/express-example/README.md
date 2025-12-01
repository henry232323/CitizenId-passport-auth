# Citizen iD Passport Example - Express.js

This is a complete example application demonstrating how to use `passport-citizenid` with Express.js.

## Features

- OAuth 2.0 authentication with Citizen iD
- OpenID Connect support
- Session management
- User profile display
- Access and refresh token handling
- Beautiful, modern UI
- Full error handling

## Setup

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment Variables

Copy the `.env.example` file to `.env`:

```bash
cp .env.example .env
```

Then edit `.env` and add your Citizen iD credentials:

```env
CITIZENID_CLIENT_ID=your-client-id-here
CITIZENID_CLIENT_SECRET=your-client-secret-here
CITIZENID_CALLBACK_URL=http://localhost:3000/auth/citizenid/callback
SESSION_SECRET=change-this-to-a-random-secret
```

### 3. Get Citizen iD Credentials

To get your Citizen iD OAuth2 credentials:

1. Visit [Citizen iD](https://citizenid.space/)
2. Create or log into your account
3. Register a new application
4. Set the callback URL to: `http://localhost:3000/auth/citizenid/callback`
5. Note your Client ID and Client Secret

### 4. Run the Application

**Production:**
```bash
npm start
```

**Development (with TypeScript compilation and auto-reload):**
```bash
npm run dev
```

**Development (direct TypeScript execution, faster):**
```bash
npm run dev:ts
```

The application will be available at: http://localhost:3000

## Project Structure

```
express-example/
├── src/
│   └── server.ts       # Main application file (TypeScript source)
├── dist/               # Compiled JavaScript (generated)
├── views/              # EJS templates
│   ├── home.ejs        # Home page
│   ├── login.ejs       # Login page
│   ├── profile.ejs     # User profile page
│   └── error.ejs       # Error page
├── package.json        # Dependencies
├── tsconfig.json       # TypeScript configuration
├── .env.example        # Environment variables template
├── .env                # Your local environment (git-ignored)
└── README.md           # This file
```

## Routes

- `GET /` - Home page (shows login button or user info)
- `GET /login` - Login page
- `GET /auth/citizenid` - Initiates OAuth flow with Citizen iD
- `GET /auth/citizenid/callback` - OAuth callback endpoint
- `GET /profile` - User profile page (requires authentication)
- `GET /logout` - Logout and clear session

## How It Works

### 1. User Authentication Flow

1. User clicks "Login with Citizen iD"
2. Application redirects to Citizen iD authorization page
3. User authenticates and authorizes the application
4. Citizen iD redirects back to callback URL with authorization code
5. Application exchanges code for access token and ID token
6. User profile is retrieved from ID token
7. User is logged in and session is created

### 2. Session Management

Sessions are managed using `express-session`. The user object (including profile and tokens) is serialized into the session.

### 3. Protected Routes

The `/profile` route is protected by the `ensureAuthenticated` middleware, which checks if the user is logged in.

## Customization

### Changing Scopes

Edit the scope array in `server.js`:

```javascript
passport.use(new CitizenIDStrategy({
    // ... other options
    scope: ['openid', 'profile', 'email', 'roles', 'offline_access']
  },
  // ...
));
```

**Note:** The `openid` scope is automatically added if missing (required for OIDC compliance).

Available scopes:
- `openid` - Required for OpenID Connect (auto-added if missing)
- `profile` - Basic profile information
- `email` - Email address
- `roles` - User roles
- `offline_access` - Refresh token

#### Custom Profile Scopes

You can also request custom profile scopes to get additional user information:

```javascript
scope: ['openid', 'profile', 'email', 'roles', 'offline_access', 'discord.profile', 'rsi.profile']
```

Custom profile scopes:
- `discord.profile` - Discord account information
- `rsi.profile` - RSI (Roberts Space Industries) account information
- `google.profile` - Google account information
- `twitch.profile` - Twitch account information

Custom claims from these scopes are available in `profile._customClaims` and displayed on the profile page.

### Custom Authorization Parameters

You can add custom parameters to the authorization request:

```javascript
app.get('/auth/citizenid',
  passport.authenticate('citizenid', {
    nonce: 'random-nonce-value',
    responseMode: 'form_post',
    prompt: 'login'
  })
);
```

## Security Considerations

1. **Always use HTTPS in production** - Set `cookie.secure: true` in session config
2. **Keep secrets secure** - Never commit `.env` file to version control
3. **Use strong session secret** - Generate a random, long secret
4. **Store tokens securely** - Consider encrypting tokens in database
5. **Validate redirect URIs** - Ensure callback URL matches registered URL

## Troubleshooting

### "Missing credentials" error

Make sure your `.env` file is properly configured with valid `CITIZENID_CLIENT_ID` and `CITIZENID_CLIENT_SECRET`.

### "Callback URL mismatch" error

Ensure the callback URL in your `.env` file matches the one registered in your Citizen iD application settings.

### Session not persisting

Check that:
1. `express-session` is properly configured
2. Cookie settings are appropriate for your environment
3. Session secret is set

## Learn More

- [Citizen iD Documentation](https://docs.citizenid.space/)
- [Passport.js Documentation](http://www.passportjs.org/)
- [Express.js Documentation](https://expressjs.com/)

## License

MIT
