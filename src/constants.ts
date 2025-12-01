/**
 * Citizen iD OAuth2 and OpenID Connect Constants
 */

/**
 * OAuth2 Scopes supported by Citizen iD
 */
export const Scopes = {
  // Standard OIDC scopes
  OPENID: 'openid',
  PROFILE: 'profile',
  EMAIL: 'email',
  ROLES: 'roles',
  OFFLINE_ACCESS: 'offline_access',
  
  // Custom profile scopes
  GOOGLE_PROFILE: 'google.profile',
  TWITCH_PROFILE: 'twitch.profile',
  DISCORD_PROFILE: 'discord.profile',
  RSI_PROFILE: 'rsi.profile',
} as const;

/**
 * Type for scope values
 */
export type Scope = typeof Scopes[keyof typeof Scopes];

/**
 * Standard scopes array (commonly used)
 */
export const STANDARD_SCOPES: Scope[] = [
  Scopes.OPENID,
  Scopes.PROFILE,
  Scopes.EMAIL,
];

/**
 * All available scopes array
 */
export const ALL_SCOPES: Scope[] = [
  Scopes.OPENID,
  Scopes.PROFILE,
  Scopes.EMAIL,
  Scopes.ROLES,
  Scopes.OFFLINE_ACCESS,
  Scopes.GOOGLE_PROFILE,
  Scopes.TWITCH_PROFILE,
  Scopes.DISCORD_PROFILE,
  Scopes.RSI_PROFILE,
];

/**
 * Custom profile claim keys for avatar URLs
 */
export const AvatarClaimKeys = {
  RSI: 'urn:user:rsi:avatar:url',
  DISCORD: 'urn:user:discord:avatar:url',
  TWITCH: 'urn:user:twitch:avatar:url',
  GOOGLE: 'urn:user:google:avatar:url',
} as const;

/**
 * Endpoint URLs for Citizen iD OAuth2/OIDC
 */
export const Endpoints = {
  PRODUCTION: {
    AUTHORITY: 'https://citizenid.space',
    AUTHORIZATION: 'https://citizenid.space/connect/authorize',
    TOKEN: 'https://citizenid.space/connect/token',
    USERINFO: 'https://citizenid.space/connect/userinfo',
    REVOKE: 'https://citizenid.space/connect/revoke',
    DISCOVERY: 'https://citizenid.space/.well-known/openid-configuration',
  },
  DEVELOPMENT: {
    AUTHORITY: 'https://dev.citizenid.space',
    AUTHORIZATION: 'https://dev.citizenid.space/connect/authorize',
    TOKEN: 'https://dev.citizenid.space/connect/token',
    USERINFO: 'https://dev.citizenid.space/connect/userinfo',
    REVOKE: 'https://dev.citizenid.space/connect/revoke',
    DISCOVERY: 'https://dev.citizenid.space/.well-known/openid-configuration',
  },
} as const;

/**
 * Helper function to get endpoints for a given authority
 */
export function getEndpoints(authority: string = Endpoints.PRODUCTION.AUTHORITY) {
  if (authority === Endpoints.DEVELOPMENT.AUTHORITY) {
    return Endpoints.DEVELOPMENT;
  }
  return Endpoints.PRODUCTION;
}
