/**
 * Module dependencies.
 */
import { Strategy as OAuth2Strategy, StrategyOptions as OAuth2StrategyOptions, VerifyFunction } from 'passport-oauth2';
import * as jwt from 'jsonwebtoken';
import { EventEmitter } from 'events';
import { Endpoints, getEndpoints, Scopes, AvatarClaimKeys, ALL_AVATAR_CLAIM_KEYS, CUSTOM_CLAIM_PREFIX } from './constants';

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
  _customClaims?: Record<string, unknown>; // Custom claims from scopes like discord.profile, rsi.profile, etc.
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
  // Custom profile claims (available when corresponding scopes are requested)
  [key: `urn:user:${string}`]: unknown;
}

/**
 * Strategy options for Citizen iD authentication.
 */
export interface CitizenIDStrategyOptions {
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
  | ((accessToken: string, refreshToken: string, params: OAuth2TokenParams, profile: CitizenIDProfile, done: PassportDoneCallback<TUser, TInfo>) => void);

/**
 * Verify function type with request parameter.
 * @template TUser - The type of the user object returned by the verify callback
 * @template TInfo - The type of additional info passed to the done callback
 * @template TRequest - The type of the Express request object
 */
export type CitizenIDVerifyFunctionWithRequest<TUser = unknown, TInfo = unknown, TRequest extends ExpressRequest = ExpressRequest> = 
  | ((req: TRequest, accessToken: string, refreshToken: string, profile: CitizenIDProfile, done: PassportDoneCallback<TUser, TInfo>) => void)
  | ((req: TRequest, accessToken: string, refreshToken: string, params: OAuth2TokenParams, profile: CitizenIDProfile, done: PassportDoneCallback<TUser, TInfo>) => void);

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
 * Options:
 *   - `clientID`          your Citizen iD application's client ID
 *   - `clientSecret`      your Citizen iD application's client secret (optional for public clients)
 *   - `callbackURL`       URL to which Citizen iD will redirect the user after granting authorization
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
  private _verify: CitizenIDVerifyFunction<unknown, unknown> | CitizenIDVerifyFunctionWithRequest<unknown, unknown>;

  constructor(
    options: CitizenIDStrategyOptions,
    verify: CitizenIDVerifyFunction<unknown, unknown> | CitizenIDVerifyFunctionWithRequest<unknown, unknown>
  ) {
    // Set default options - use production endpoints by default
    // If authorizationURL is provided, try to detect the environment from it
    const providedAuthority = options.authorizationURL 
      ? options.authorizationURL.replace('/connect/authorize', '').replace('/connect/token', '').replace('/connect/userinfo', '')
      : undefined;
    const endpoints = getEndpoints(providedAuthority || Endpoints.PRODUCTION.AUTHORITY);
    options.authorizationURL = options.authorizationURL || endpoints.AUTHORIZATION;
    options.tokenURL = options.tokenURL || endpoints.TOKEN;
    options.userInfoURL = options.userInfoURL || endpoints.USERINFO;
    
    // Ensure 'openid' scope is always included (required for OIDC)
    options.scope = options.scope || [Scopes.OPENID, Scopes.PROFILE, Scopes.EMAIL];
    if (!Array.isArray(options.scope)) {
      options.scope = [options.scope];
    }
    // Check if openid scope is included (handle both string and constant)
    const hasOpenId = options.scope.some(s => s === 'openid' || s === Scopes.OPENID);
    if (!hasOpenId) {
      options.scope.unshift(Scopes.OPENID);
    }
    
    // Enable PKCE by default (recommended for security)
    if (options.pkce === undefined) {
      options.pkce = true;
    }
    
    // Enable state parameter by default
    if (options.state === undefined) {
      options.state = true;
    }

    // Store userInfoURL for later use
    const userInfoURL = options.userInfoURL;
    
    // Call the parent constructor with properly typed options
    // Note: verify needs to be cast because passport-oauth2's types are restrictive
    super(options as OAuth2StrategyOptions, verify as VerifyFunction);
    
    this.name = 'citizenid';
    this._userInfoURL = userInfoURL;
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
   *   - `_raw`             the raw user info response
   *   - `_json`            the JSON parsed user info
   *
   * @param {String} accessToken
   * @param {Function} done
   * @api protected
   */
  userProfile(accessToken: string, done: (err?: Error | null, profile?: CitizenIDProfile) => void): void {
    // First, try to decode the ID token if available
    // The ID token is typically returned with the access token
    if (this._idToken) {
      try {
        // Decode without verification (verification should be done server-side if needed)
        const decoded = jwt.decode(this._idToken) as CitizenIDUserInfo | null;
        
        if (decoded) {
          const profile = this._normalizeProfile(decoded, this._idToken);
          return done(null, profile);
        }
      } catch (err) {
        // If decoding fails, fall back to userinfo endpoint
      }
    }
    
    // Fall back to calling the userinfo endpoint
    // Accessing private _oauth2 property from parent class - necessary for functionality
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (this as any)._oauth2.get(this._userInfoURL, accessToken, (err: Error | null, body: string, res: unknown) => {
      if (err) {
        const error = new Error('Failed to fetch user profile');
        // Node.js Error.cause is available in Node 16.9+, but TypeScript types may not reflect this
        // Using type assertion for compatibility
        if ('cause' in Error.prototype || typeof (err as { cause?: unknown }).cause !== 'undefined') {
          (error as { cause?: unknown }).cause = err;
        }
        return done(error);
      }
      
      try {
        const json = JSON.parse(body) as CitizenIDUserInfo;
        const profile = this._normalizeProfile(json, body);
        
        done(null, profile);
      } catch (ex) {
        const error = new Error('Failed to parse user profile');
        // Node.js Error.cause is available in Node 16.9+, but TypeScript types may not reflect this
        if ('cause' in Error.prototype || typeof (ex as { cause?: unknown }).cause !== 'undefined') {
          (error as { cause?: unknown }).cause = ex;
        }
        done(error);
      }
    });
  }

  /**
   * Normalize user profile data from Citizen iD.
   *
   * @param {CitizenIDUserInfo} json - The user data from ID token or userinfo endpoint
   * @param {String} raw - The raw response
   * @return {CitizenIDProfile} Normalized profile
   * @api private
   */
  private _normalizeProfile(json: CitizenIDUserInfo, raw: string): CitizenIDProfile {
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
    const self = this;
    // Accessing protected method from parent class - necessary for functionality
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const originalGetOAuthAccessToken = (OAuth2Strategy.prototype as any).getOAuthAccessToken;
    
    originalGetOAuthAccessToken.call(this, code, params, (err: Error | null, accessToken?: string, refreshToken?: string, params?: OAuth2TokenParams) => {
      if (err) {
        return callback(err);
      }
      
      // Store the ID token for profile extraction
      if (params && params.id_token) {
        self._idToken = params.id_token;
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
export * from './constants';
import * as Constants from './constants';

/**
 * CommonJS module interface that includes the Strategy class and all constants
 */
interface CitizenIDModule {
  Strategy: typeof Strategy;
  default: typeof Strategy;
  Scopes: typeof Constants.Scopes;
  Endpoints: typeof Constants.Endpoints;
  AvatarClaimKeys: typeof Constants.AvatarClaimKeys;
  ALL_AVATAR_CLAIM_KEYS: typeof Constants.ALL_AVATAR_CLAIM_KEYS;
  CUSTOM_CLAIM_PREFIX: typeof Constants.CUSTOM_CLAIM_PREFIX;
  AVATAR_URL_SUFFIX: typeof Constants.AVATAR_URL_SUFFIX;
  Roles: typeof Constants.Roles;
  LegacyRoles: typeof Constants.LegacyRoles;
  STANDARD_SCOPES: typeof Constants.STANDARD_SCOPES;
  ALL_SCOPES: typeof Constants.ALL_SCOPES;
  getEndpoints: typeof Constants.getEndpoints;
}

// Export as default and named export for CommonJS compatibility
export default Strategy;

// Create properly typed CommonJS export
const moduleExports: CitizenIDModule = {
  Strategy,
  default: Strategy,
  Scopes: Constants.Scopes,
  Endpoints: Constants.Endpoints,
  AvatarClaimKeys: Constants.AvatarClaimKeys,
  ALL_AVATAR_CLAIM_KEYS: Constants.ALL_AVATAR_CLAIM_KEYS,
  CUSTOM_CLAIM_PREFIX: Constants.CUSTOM_CLAIM_PREFIX,
  AVATAR_URL_SUFFIX: Constants.AVATAR_URL_SUFFIX,
  Roles: Constants.Roles,
  LegacyRoles: Constants.LegacyRoles,
  STANDARD_SCOPES: Constants.STANDARD_SCOPES,
  ALL_SCOPES: Constants.ALL_SCOPES,
  getEndpoints: Constants.getEndpoints,
};

// Export for CommonJS
module.exports = moduleExports;
