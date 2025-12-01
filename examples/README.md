# Examples

This directory contains example applications demonstrating how to use `passport-citizenid`.

## Express.js Example

The `express-example` directory contains a complete Express.js application with Citizen iD authentication (TypeScript source in `src/server.ts`).

There is also a standalone example in `src/standalone-example.ts` that demonstrates a simpler setup.

### Setup

1. Install dependencies:
```bash
npm install express express-session passport
```

2. Get your client credentials by registering an application with Citizen iD. See the [Citizen iD OAuth2 Documentation](https://docs.citizenid.space/integrator-guide/oauth2/) for instructions.

3. Set environment variables:
```bash
export CITIZENID_CLIENT_ID="your-client-id"
export CITIZENID_CLIENT_SECRET="your-client-secret"  # Optional for public clients
export CALLBACK_URL="http://localhost:3000/auth/citizenid/callback"
export SESSION_SECRET="your-session-secret"
```

4. Run the example:
```bash
cd express-example
npm install
npm start
```

5. Visit `http://localhost:3000` in your browser and click "Login with Citizen iD"

### Features Demonstrated

- Basic authentication flow
- Session management
- User profile display
- Role-based access
- Protected routes
- Logout functionality

### Notes

- The example uses in-memory sessions. In production, use a proper session store (e.g., Redis, MongoDB).
- User data is stored in the session. In production, store user data in a database.
- The example includes basic HTML for demonstration. In production, use a proper templating engine or frontend framework.
