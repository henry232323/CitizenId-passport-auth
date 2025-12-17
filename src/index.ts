/**
 * Module dependencies.
 */
import { Strategy as OAuth2Strategy, StrategyOptions as OAuth2StrategyOptions, VerifyFunction } from 'passport-oauth2';
import * as jwt from 'jsonwebtoken';
import { 
  Endpoints, 
  getEndpoints, 
  Scopes, 
  AvatarClaimKeys, 
  ALL_AVATAR_CLAIM_KEYS, 
  CUSTOM_CLAIM_PREFIX,
  GoogleClaimKeys,
  TwitchClaimKeys,
  DiscordClaimKeys,
  RSIClaimKeys
} from './constants.js';

/**
 * Helper function to set error cause (for Node.js 16.9+ compatibility)
 * @param error - The error to set the cause on
 * @param cause - The cause of the error
 */
function setErrorCause(error: Error, cause: unknown): void {
  // Node.js Error.cause is available in Node 16.9+, but TypeScript types may not reflect this
  // Using type assertion for compatibility
  try {
    (error as { cause?: unknown }).cause = cause;
  } catch {
    // If setting cause fails, ignore (older Node.js versions)
  }
}

/**
 * Google profile custom claims (available when google.profile scope is requested).
 * Reference: https://docs.citizenid.space/integrator-guide/oauth2/scopes-claims
 */
export interface GoogleProfileClaims {
  [GoogleClaimKeys.AVATAR_URL]?: string;
  [GoogleClaimKeys.EMAIL]?: string;
  [GoogleClaimKeys.NAME]?: string;
  [GoogleClaimKeys.ACCOUNT_ID]?: string;
}

/**
 * Twitch profile custom claims (available when twitch.profile scope is requested).
 * Reference: https://docs.citizenid.space/integrator-guide/oauth2/scopes-claims
 */
export interface TwitchProfileClaims {
  [TwitchClaimKeys.AVATAR_URL]?: string;
  [TwitchClaimKeys.EMAIL]?: string;
  [TwitchClaimKeys.USERNAME]?: string;
  [TwitchClaimKeys.ACCOUNT_ID]?: string;
}

/**
 * Discord profile custom claims (available when discord.profile scope is requested).
 * Reference: https://docs.citizenid.space/integrator-guide/oauth2/scopes-claims
 */
export interface DiscordProfileClaims {
  [DiscordClaimKeys.AVATAR_URL]?: string;
  [DiscordClaimKeys.USERNAME]?: string;
  [DiscordClaimKeys.ACCOUNT_ID]?: string;
  [DiscordClaimKeys.SCOPES]?: string | string[];
}

/**
 * RSI profile custom claims (available when rsi.profile scope is requested).
 * Reference: https://docs.citizenid.space/integrator-guide/oauth2/scopes-claims
 */
export interface RSIProfileClaims {
  [RSIClaimKeys.AVATAR_URL]?: string;
  [RSIClaimKeys.USERNAME]?: string;
  [RSIClaimKeys.ENLISTED_AT]?: string;
  [RSIClaimKeys.CITIZEN_ID]?: string;
  [RSIClaimKeys.SPECTRUM_ID]?: string;
}

/**
 * All custom profile claims combined.
 */
export interface CustomProfileClaims {
  google?: GoogleProfileClaims;
  twitch?: TwitchProfileClaims;
  discord?: DiscordProfileClaims;
  rsi?: RSIProfileClaims;
}

/**
 * User profile information from Citizen iD.
 */
export interface CitizenIDProfile {
  provider: 'citizenid';
  id: string;
  username: string;
  displayName: string;
  emails: Array<{
    value: string;
    verified: boolean;
  }>;
  roles: string[];
  photos?: Array<{
    value: string;
  }>;
  authorizationId?: string;
  // Typed custom claims (populated when corresponding scopes are requested)
  google?: GoogleProfileClaims;
  twitch?: TwitchProfileClaims;
  discord?: DiscordProfileClaims;
  rsi?: RSIProfileClaims;
  // Raw custom claims object (for backward compatibility and access to all urn:user:* claims)
  _customClaims?: Record<string, unknown>;
  _raw: string;
  _json: CitizenIDUserInfo;
}

/**
 * User info from ID token or userinfo endpoint.
 */
export interface CitizenIDUserInfo {
  sub: string;
  name?: string;
  preferred_username?: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
  role?: string | string[];
  oi_au_id?: string;
  iss?: string;
  aud?: string;
  exp?: number;
  iat?: number;
  nonce?: string;
  at_hash?: string;
  oi_tkn_id?: string;
  azp?: string;
  // Typed Google profile claims (available when google.profile scope is requested)
  // Reference: https://docs.citizenid.space/integrator-guide/oauth2/scopes-claims
  [GoogleClaimKeys.AVATAR_URL]?: string;
  [GoogleClaimKeys.EMAIL]?: string;
  [GoogleClaimKeys.NAME]?: string;
  [GoogleClaimKeys.ACCOUNT_ID]?: string;
  // Typed Twitch profile claims (available when twitch.profile scope is requested)
  [TwitchClaimKeys.AVATAR_URL]?: string;
  [TwitchClaimKeys.EMAIL]?: string;
  [TwitchClaimKeys.USERNAME]?: string;
  [TwitchClaimKeys.ACCOUNT_ID]?: string;
  // Typed Discord profile claims (available when discord.profile scope is requested)
  [DiscordClaimKeys.AVATAR_URL]?: string;
  [DiscordClaimKeys.USERNAME]?: string;
  [DiscordClaimKeys.ACCOUNT_ID]?: string;
  [DiscordClaimKeys.SCOPES]?: string | string[];
  // Typed RSI profile claims (available when rsi.profile scope is requested)
  [RSIClaimKeys.AVATAR_URL]?: string;
  [RSIClaimKeys.USERNAME]?: string;
  [RSIClaimKeys.ENLISTED_AT]?: string;
  [RSIClaimKeys.CITIZEN_ID]?: string;
  [RSIClaimKeys.SPECTRUM_ID]?: string;
  // Allow other custom claims with urn:user: prefix (for future extensibility)
  [key: `urn:user:${string}`]: unknown;
}

/**
 * Strategy options for Citizen iD authentication.
 */
export interface CitizenIDStrategyOptions {
  /**
   * Authority (base URL) for Citizen iD (e.g., https://citizenid.space or https://dev.citizenid.space).
   * If provided, endpoints are derived automatically via getEndpoints(authority).
   */
  authority?: string;

  /**
   * Optional explicit endpoints. If provided, these override derived or default endpoints.
   */
  endpoints?: {
    authorizationURL?: string;
    tokenURL?: string;
    userInfoURL?: string;
    revokeURL?: string;
    discoveryURL?: string;
  };

  /**
   * Your Citizen iD application's client ID.
   */
  clientID: string;
  
  /**
   * Your Citizen iD application's client secret.
   * Optional for public clients using PKCE.
   */
  clientSecret?: string;
  
  /**
   * URL to which Citizen iD will redirect the user after authorization.
   */
  callbackURL: string;
  
  /**
   * Array of permission scopes to request.
   * @default [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL]
   */
  scope?: string[];
  
  /**
   * Authorization endpoint URL.
   * @default Endpoints.PRODUCTION.AUTHORIZATION
   */
  authorizationURL?: string;
  
  /**
   * Token endpoint URL.
   * @default Endpoints.PRODUCTION.TOKEN
   */
  tokenURL?: string;
  
  /**
   * UserInfo endpoint URL.
   * @default Endpoints.PRODUCTION.USERINFO
   */
  userInfoURL?: string;
  
  /**
   * Enable PKCE (Proof Key for Code Exchange).
   * @default true
   */
  pkce?: boolean;
  
  /**
   * Enable state parameter for CSRF protection.
   * @default true
   */
  state?: boolean;
  
  /**
   * Store state in session (when state is enabled).
   * @default true
   */
  store?: unknown;
  
  /**
   * Pass request to verify callback.
   * @default false
   */
  passReqToCallback?: boolean;
  
  // Allow other OAuth2StrategyOptions
  [key: string]: unknown;
}

/**
 * Authorization parameters for OAuth2 request.
 */
export interface CitizenIDAuthorizationParams {
  /**
   * Nonce value for OIDC security.
   */
  nonce?: string;
  
  /**
   * Response mode (e.g., 'form_post', 'query', 'fragment').
   */
  responseMode?: string;
  
  /**
   * Prompt parameter (e.g., 'login', 'consent', 'none').
   */
  prompt?: string;
  
  /**
   * Maximum authentication age in seconds.
   */
  maxAge?: number;
  
  /**
   * UI locales for the authorization interface.
   */
  uiLocales?: string;
}

/**
 * Passport.js done callback type with generic user and info types
 * @template TUser - The type of the user object (defaults to unknown)
 * @template TInfo - The type of additional info (defaults to unknown)
 */
export type PassportDoneCallback<TUser = unknown, TInfo = unknown> = (
  error: Error | null,
  user?: TUser,
  info?: TInfo
) => void;

/**
 * Express Request type (minimal interface for type safety)
 * @template T - Additional properties to extend the request object
 */
export interface ExpressRequest<T extends Record<string, unknown> = Record<string, unknown>> {
  [key: string]: unknown;
}

/**
 * Type that accepts both Express Request and our ExpressRequest interface
 * This is intentionally permissive to accept any request-like object
 */
export type AnyRequest = ExpressRequest | { [key: string]: unknown } | any

/**
 * OAuth2 token response parameters
 * Additional fields may be present in the token response
 */
export interface OAuth2TokenParams {
  id_token?: string;
  expires_in?: number;
  token_type?: string;
  scope?: string;
  [key: string]: unknown;
}

/**
 * Verify function type for Citizen iD strategy.
 * @template TUser - The type of the user object returned by the verify callback
 * @template TInfo - The type of additional info passed to the done callback
 */
export type CitizenIDVerifyFunction<TUser = unknown, TInfo = unknown> = 
  | ((accessToken: string, refreshToken: string, profile: CitizenIDProfile, done: PassportDoneCallback<TUser, TInfo>) => void)
  | ((accessToken: string, refreshToken: string, profile: CitizenIDProfile, done: PassportDoneCallback<TUser, TInfo>) => Promise<void>)
  | ((accessToken: string, refreshToken: string, params: OAuth2TokenParams, profile: CitizenIDProfile, done: PassportDoneCallback<TUser, TInfo>) => void)
  | ((accessToken: string, refreshToken: string, params: OAuth2TokenParams, profile: CitizenIDProfile, done: PassportDoneCallback<TUser, TInfo>) => Promise<void>);

/**
 * Verify function type with request parameter.
 * @template TUser - The type of the user object returned by the verify callback
 * @template TInfo - The type of additional info passed to the done callback
 * @template TRequest - The type of the Express request object
 */
export type CitizenIDVerifyFunctionWithRequest<TUser = unknown, TInfo = unknown, TRequest extends AnyRequest = AnyRequest> = 
  | ((req: TRequest, accessToken: string, refreshToken: string, profile: CitizenIDProfile, done: PassportDoneCallback<TUser, TInfo>) => void)
  | ((req: TRequest, accessToken: string, refreshToken: string, profile: CitizenIDProfile, done: PassportDoneCallback<TUser, TInfo>) => Promise<void>)
  | ((req: TRequest, accessToken: string, refreshToken: string, params: OAuth2TokenParams, profile: CitizenIDProfile, done: PassportDoneCallback<TUser, TInfo>) => void)
  | ((req: TRequest, accessToken: string, refreshToken: string, params: OAuth2TokenParams, profile: CitizenIDProfile, done: PassportDoneCallback<TUser, TInfo>) => Promise<void>);

  /**
   * `Strategy` constructor.
   *
   * The Citizen iD authentication strategy authenticates requests by delegating to
   * Citizen iD using the OAuth 2.0 protocol with OpenID Connect.
   *
   * Applications must supply a `verify` callback which accepts an `accessToken`,
   * `refreshToken` and service-specific `profile`, and then calls the `done`
   * callback supplying a `user`, which should be set to `false` if the
   * credentials are not valid. If an exception occurred, `err` should be set.
   *
   * @param {CitizenIDStrategyOptions} options - Strategy configuration options
   * @param {CitizenIDVerifyFunction | CitizenIDVerifyFunctionWithRequest} verify - Verify callback function
   * @throws {Error} If required options are missing or invalid
   *
   * Options:
   *   - `clientID`          your Citizen iD application's client ID (required)
   *   - `clientSecret`      your Citizen iD application's client secret (optional for public clients)
   *   - `callbackURL`       URL to which Citizen iD will redirect the user after granting authorization (required)
   *   - `scope`             array of permission scopes to request (default: [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL])
   *   - `authorizationURL`  URL used to obtain an authorization grant (default: Endpoints.PRODUCTION.AUTHORIZATION)
   *   - `tokenURL`          URL used to obtain an access token (default: Endpoints.PRODUCTION.TOKEN)
   *   - `userInfoURL`       URL used to obtain user info (default: Endpoints.PRODUCTION.USERINFO)
   *   - `pkce`              enable PKCE (default: true)
   *   - `state`             enable state parameter (default: true)
   *
   * Examples:
 *
 *     passport.use(new CitizenIDStrategy({
 *         clientID: 'a3a5953f-8ab0-4d39-a407-d3f0cc9f94da',
 *         clientSecret: 'your-client-secret',
 *         callbackURL: 'https://www.example.com/auth/citizenid/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate({ citizenId: profile.id }, function (err, user) {
 *           return done(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {CitizenIDStrategyOptions} options
 * @param {CitizenIDVerifyFunction | CitizenIDVerifyFunctionWithRequest} verify
 * @api public
 */
export class Strategy extends OAuth2Strategy {
  name: string;
  private _userInfoURL: string;
  private _idToken?: string;
  private _verify: CitizenIDVerifyFunction<unknown, unknown> | CitizenIDVerifyFunctionWithRequest<unknown, unknown, AnyRequest>;

  constructor(
    options: CitizenIDStrategyOptions,
    verify: CitizenIDVerifyFunction<unknown, unknown> | CitizenIDVerifyFunctionWithRequest<unknown, unknown, AnyRequest>
  ) {
    // Validate required options
    if (!options.clientID) {
      throw new Error('CitizenIDStrategy requires a clientID option');
    }
    if (!options.callbackURL) {
      throw new Error('CitizenIDStrategy requires a callbackURL option');
    }
    if (!verify || typeof verify !== 'function') {
      throw new Error('CitizenIDStrategy requires a verify callback function');
    }
    
    // Resolve endpoints
    // Priority:
    // 1) Explicit endpoints option
    // 2) authority option via getEndpoints(authority)
    // 3) authority inferred from provided authorizationURL
    // 4) defaults (production)
    let resolvedAuthority: string | undefined = options.authority;
    if (!resolvedAuthority && options.authorizationURL) {
      const urlMatch = options.authorizationURL.match(/^https?:\/\/([^/]+)/);
      if (urlMatch) {
        resolvedAuthority = `https://${urlMatch[1]}`;
      }
    }
    const derivedEndpoints = getEndpoints(resolvedAuthority || Endpoints.PRODUCTION.AUTHORITY);
    const endpointsOverride = options.endpoints || {};
    options.authorizationURL = options.authorizationURL || endpointsOverride.authorizationURL || derivedEndpoints.AUTHORIZATION;
    options.tokenURL = options.tokenURL || endpointsOverride.tokenURL || derivedEndpoints.TOKEN;
    options.userInfoURL = options.userInfoURL || endpointsOverride.userInfoURL || derivedEndpoints.USERINFO;
    
    // Ensure 'openid' scope is always included (required for OIDC)
    if (!options.scope) {
      options.scope = [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL];
    } else if (!Array.isArray(options.scope)) {
      options.scope = [options.scope];
    }
    const hasOpenId = options.scope.some(s => s === 'openid' || s === Scopes.OPENID);
    if (!hasOpenId) {
      options.scope.unshift(Scopes.OPENID);
    }
    
    // Enable PKCE and state by default
    if (options.pkce === undefined) options.pkce = true;
    if (options.state === undefined) options.state = true;
    
    // Enable passReqToCallback based on verify arity
    const fnLength = (verify as Function).length;
    const hasRequestParam = fnLength >= 5;
    const hasParamsParam = hasRequestParam ? fnLength === 6 : fnLength === 5;
    if (hasRequestParam && options.passReqToCallback === undefined) {
      options.passReqToCallback = true;
    }
    
    // Wrap verify to adapt to passport-oauth2 calling convention (params may be inserted)
    const wrappedVerify: VerifyFunction = (...args: any[]) => {
      if (hasRequestParam && options.passReqToCallback) {
        // passport-oauth2 passes: req, accessToken, refreshToken, params, profile, done
        const req = args[0] as AnyRequest;
        const accessToken = args[1] as string;
        const refreshToken = args[2] as string;
        const params = args[3] as OAuth2TokenParams;
        const profile = args[4] as CitizenIDProfile;
        const done = args[5] as PassportDoneCallback<unknown, unknown>;
        if (hasParamsParam) {
          return (verify as (
            req: AnyRequest,
            accessToken: string,
            refreshToken: string,
            params: OAuth2TokenParams,
            profile: CitizenIDProfile,
            done: PassportDoneCallback<unknown, unknown>
          ) => void | Promise<void>)(req, accessToken, refreshToken, params, profile, done);
        }
        return (verify as (
          req: AnyRequest,
          accessToken: string,
          refreshToken: string,
          profile: CitizenIDProfile,
          done: PassportDoneCallback<unknown, unknown>
        ) => void | Promise<void>)(req, accessToken, refreshToken, profile, done);
      } else {
        // passport-oauth2 passes: accessToken, refreshToken, params, profile, done
        const accessToken = args[0] as string;
        const refreshToken = args[1] as string;
        const params = args[2] as OAuth2TokenParams;
        const profile = args[3] as CitizenIDProfile;
        const done = args[4] as PassportDoneCallback<unknown, unknown>;
        if (hasParamsParam) {
          return (verify as (
            accessToken: string,
            refreshToken: string,
            params: OAuth2TokenParams,
            profile: CitizenIDProfile,
            done: PassportDoneCallback<unknown, unknown>
          ) => void | Promise<void>)(accessToken, refreshToken, params, profile, done);
        }
        return (verify as (
          accessToken: string,
          refreshToken: string,
          profile: CitizenIDProfile,
          done: PassportDoneCallback<unknown, unknown>
        ) => void | Promise<void>)(accessToken, refreshToken, profile, done);
      }
    };
    
    // Call the parent constructor with wrapped verify
    super(options as OAuth2StrategyOptions, wrappedVerify);
    
    this.name = 'citizenid';
    this._userInfoURL = options.userInfoURL;
    this._verify = verify;
    
    // Use authorization header for GET requests
    // Accessing private _oauth2 property from parent class - necessary for functionality
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (this as any)._oauth2.useAuthorizationHeaderforGET(true);
  }

  /**
   * Retrieve user profile from Citizen iD.
   *
   * This function constructs a normalized profile, with the following properties:
   *
   *   - `provider`         always set to `citizenid`
   *   - `id`               the user's Citizen iD ID (sub claim)
   *   - `username`         the user's Citizen iD username (preferred_username)
   *   - `displayName`      the user's full name (name)
   *   - `emails`           the user's email addresses
   *   - `roles`            the user's roles
   *   - `google`           typed Google profile claims (when google.profile scope is requested)
   *   - `twitch`           typed Twitch profile claims (when twitch.profile scope is requested)
   *   - `discord`           typed Discord profile claims (when discord.profile scope is requested)
   *   - `rsi`              typed RSI profile claims (when rsi.profile scope is requested)
   *   - `_customClaims`    all custom claims (urn:user:*) for backward compatibility
   *   - `_raw`             the raw user info response
   *   - `_json`            the JSON parsed user info
   *
   * @param {String} accessToken - The OAuth2 access token
   * @param {Function} done - Callback function (err, profile)
   * @throws {Error} If the access token is invalid or the profile cannot be retrieved
   * @api protected
   */
  userProfile(accessToken: string, done: (err?: Error | null, profile?: CitizenIDProfile) => void): void {
    if (!accessToken || typeof accessToken !== 'string') {
      return done(new Error('Access token is required'));
    }
    // First, try to decode the ID token if available
    // The ID token is typically returned with the access token
    if (this._idToken) {
      try {
        // Decode without verification (verification should be done server-side if needed)
        const decoded = jwt.decode(this._idToken, { complete: false }) as CitizenIDUserInfo | null;
        
        if (decoded && decoded.sub) {
          const profile = this._normalizeProfile(decoded, this._idToken);
          return done(null, profile);
        }
      } catch (err) {
        // If decoding fails, fall back to userinfo endpoint
        // Error is silently ignored to allow fallback
        // This is expected behavior - ID token may not always be available or valid
      }
    }
    
    // Fall back to calling the userinfo endpoint
    // Accessing private _oauth2 property from parent class - necessary for functionality
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (this as any)._oauth2.get(this._userInfoURL, accessToken, (err: Error | null, body: string, res: unknown) => {
      if (err) {
        const error = new Error('Failed to fetch user profile from Citizen iD userinfo endpoint');
        setErrorCause(error, err);
        return done(error);
      }
      
      if (!body) {
        const error = new Error('Empty response from Citizen iD userinfo endpoint');
        return done(error);
      }
      
      try {
        const json = JSON.parse(body) as CitizenIDUserInfo;
        
        // Validate that we have at least a sub claim (required for OIDC)
        if (!json.sub) {
          const error = new Error('Invalid user profile: missing required "sub" claim');
          return done(error);
        }
        
        const profile = this._normalizeProfile(json, body);
        done(null, profile);
      } catch (ex) {
        const error = new Error('Failed to parse user profile response from Citizen iD');
        setErrorCause(error, ex);
        done(error);
      }
    });
  }

  /**
   * Normalize user profile data from Citizen iD.
   *
   * This function constructs a normalized profile with the following properties:
   *   - `provider`         always set to `citizenid`
   *   - `id`               the user's Citizen iD ID (sub claim)
   *   - `username`         the user's Citizen iD username (preferred_username)
   *   - `displayName`      the user's full name (name)
   *   - `emails`           the user's email addresses
   *   - `roles`            the user's roles
   *   - `google`           typed Google profile claims (when google.profile scope is requested)
   *   - `twitch`           typed Twitch profile claims (when twitch.profile scope is requested)
   *   - `discord`           typed Discord profile claims (when discord.profile scope is requested)
   *   - `rsi`              typed RSI profile claims (when rsi.profile scope is requested)
   *   - `_customClaims`    all custom claims (urn:user:*) for backward compatibility
   *   - `_raw`             the raw user info response
   *   - `_json`            the JSON parsed user info
   *
   * @param {CitizenIDUserInfo} json - The user data from ID token or userinfo endpoint
   * @param {String} raw - The raw response
   * @return {CitizenIDProfile} Normalized profile
   * @throws {Error} If the profile data is invalid (missing required 'sub' claim)
   * @api private
   */
  private _normalizeProfile(json: CitizenIDUserInfo, raw: string): CitizenIDProfile {
    // Validate required fields
    if (!json.sub) {
      throw new Error('Invalid profile data: missing required "sub" claim');
    }
    
    const profile: CitizenIDProfile = {
      provider: 'citizenid',
      id: json.sub,
      username: json.preferred_username || '',
      displayName: json.name || json.preferred_username || '',
      emails: [],
      roles: [],
      _raw: raw,
      _json: json
    };
    
    // Add email if available
    if (json.email) {
      profile.emails.push({
        value: json.email,
        verified: json.email_verified || false
      });
    }
    
    // Add roles if available
    if (json.role) {
      profile.roles = Array.isArray(json.role) ? json.role : [json.role];
    }
    
    if (json.oi_au_id) {
      profile.authorizationId = json.oi_au_id;
    }
    
    // Add custom profile claims (discord, rsi, google, twitch) if available
    // These are prefixed with 'urn:user:' and available when corresponding scopes are requested
    // Reference: https://docs.citizenid.space/integrator-guide/oauth2/scopes-claims
    const customClaims: Record<string, unknown> = {};
    const avatarUrls: string[] = [];
    
    // Extract all custom claims (prefixed with 'urn:user:')
    // Cast through unknown since CitizenIDUserInfo has an index signature for urn:user:* keys
    const jsonRecord = json as unknown as Record<string, unknown>;
    Object.keys(jsonRecord).forEach(key => {
      if (key.startsWith(CUSTOM_CLAIM_PREFIX)) {
        customClaims[key] = jsonRecord[key];
      }
    });
    
    // Extract and populate typed Google profile claims
    if (json[GoogleClaimKeys.AVATAR_URL] || json[GoogleClaimKeys.EMAIL] || 
        json[GoogleClaimKeys.NAME] || json[GoogleClaimKeys.ACCOUNT_ID]) {
      profile.google = {
        [GoogleClaimKeys.AVATAR_URL]: json[GoogleClaimKeys.AVATAR_URL],
        [GoogleClaimKeys.EMAIL]: json[GoogleClaimKeys.EMAIL],
        [GoogleClaimKeys.NAME]: json[GoogleClaimKeys.NAME],
        [GoogleClaimKeys.ACCOUNT_ID]: json[GoogleClaimKeys.ACCOUNT_ID],
      };
    }
    
    // Extract and populate typed Twitch profile claims
    if (json[TwitchClaimKeys.AVATAR_URL] || json[TwitchClaimKeys.EMAIL] || 
        json[TwitchClaimKeys.USERNAME] || json[TwitchClaimKeys.ACCOUNT_ID]) {
      profile.twitch = {
        [TwitchClaimKeys.AVATAR_URL]: json[TwitchClaimKeys.AVATAR_URL],
        [TwitchClaimKeys.EMAIL]: json[TwitchClaimKeys.EMAIL],
        [TwitchClaimKeys.USERNAME]: json[TwitchClaimKeys.USERNAME],
        [TwitchClaimKeys.ACCOUNT_ID]: json[TwitchClaimKeys.ACCOUNT_ID],
      };
    }
    
    // Extract and populate typed Discord profile claims
    if (json[DiscordClaimKeys.AVATAR_URL] || json[DiscordClaimKeys.USERNAME] || 
        json[DiscordClaimKeys.ACCOUNT_ID] || json[DiscordClaimKeys.SCOPES]) {
      profile.discord = {
        [DiscordClaimKeys.AVATAR_URL]: json[DiscordClaimKeys.AVATAR_URL],
        [DiscordClaimKeys.USERNAME]: json[DiscordClaimKeys.USERNAME],
        [DiscordClaimKeys.ACCOUNT_ID]: json[DiscordClaimKeys.ACCOUNT_ID],
        [DiscordClaimKeys.SCOPES]: json[DiscordClaimKeys.SCOPES],
      };
    }
    
    // Extract and populate typed RSI profile claims
    if (json[RSIClaimKeys.AVATAR_URL] || json[RSIClaimKeys.USERNAME] || 
        json[RSIClaimKeys.ENLISTED_AT] || json[RSIClaimKeys.CITIZEN_ID] || 
        json[RSIClaimKeys.SPECTRUM_ID]) {
      profile.rsi = {
        [RSIClaimKeys.AVATAR_URL]: json[RSIClaimKeys.AVATAR_URL],
        [RSIClaimKeys.USERNAME]: json[RSIClaimKeys.USERNAME],
        [RSIClaimKeys.ENLISTED_AT]: json[RSIClaimKeys.ENLISTED_AT],
        [RSIClaimKeys.CITIZEN_ID]: json[RSIClaimKeys.CITIZEN_ID],
        [RSIClaimKeys.SPECTRUM_ID]: json[RSIClaimKeys.SPECTRUM_ID],
      };
    }
    
    // Extract avatar URLs using known avatar claim keys
    ALL_AVATAR_CLAIM_KEYS.forEach(avatarKey => {
      const avatarUrl = jsonRecord[avatarKey];
      if (avatarUrl && typeof avatarUrl === 'string') {
        avatarUrls.push(avatarUrl);
      }
    });
    
    // Add photos from avatar URLs if available
    if (avatarUrls.length > 0) {
      profile.photos = avatarUrls.map(url => ({ value: url }));
    }
    
    // Store all custom claims in _customClaims for backward compatibility
    if (Object.keys(customClaims).length > 0) {
      profile._customClaims = customClaims;
    }
    
    return profile;
  }

  /**
   * Override token request to capture ID token.
   *
   * @param {String} code
   * @param {Object} params
   * @param {Function} callback
   * @api protected
   */
  getOAuthAccessToken(code: string, params: Record<string, unknown>, callback: (err: Error | null, accessToken?: string, refreshToken?: string, params?: OAuth2TokenParams) => void): void {
    // Accessing protected method from parent class - necessary for functionality
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const originalGetOAuthAccessToken = (OAuth2Strategy.prototype as any).getOAuthAccessToken;
    
    originalGetOAuthAccessToken.call(this, code, params, (err: Error | null, accessToken?: string, refreshToken?: string, params?: OAuth2TokenParams) => {
      if (err) {
        return callback(err);
      }
      
      // Store the ID token for profile extraction
      if (params?.id_token && typeof params.id_token === 'string') {
        this._idToken = params.id_token;
      }
      
      callback(null, accessToken, refreshToken, params);
    });
  }

  /**
   * Return extra parameters to be included in the authorization request.
   *
   * @param {CitizenIDAuthorizationParams} options
   * @return {Object}
   * @api protected
   */
  authorizationParams(options: CitizenIDAuthorizationParams): Record<string, string | number> {
    const params: Record<string, string | number> = {};
    
    // Add nonce for OIDC (recommended for security)
    if (options.nonce) {
      params.nonce = options.nonce;
    }
    
    // Support for response_mode (e.g., form_post)
    if (options.responseMode) {
      params.response_mode = options.responseMode;
    }
    
    // Support for prompt parameter (e.g., login, consent, none)
    if (options.prompt) {
      params.prompt = options.prompt;
    }
    
    // Support for max_age parameter
    if (options.maxAge) {
      params.max_age = options.maxAge;
    }
    
    // Support for ui_locales parameter
    if (options.uiLocales) {
      params.ui_locales = options.uiLocales;
    }
    
    return params;
  }

}

// Export constants
export * from './constants.js';

// Export as default
export default Strategy;
