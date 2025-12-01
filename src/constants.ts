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
 * Array of all avatar claim keys for easy iteration
 */
export const ALL_AVATAR_CLAIM_KEYS = Object.values(AvatarClaimKeys);

/**
 * Prefix for custom user claims
 */
export const CUSTOM_CLAIM_PREFIX = 'urn:user:';

/**
 * Suffix for avatar URL claims
 */
export const AVATAR_URL_SUFFIX = ':avatar:url';

/**
 * System-wide roles that can be assigned to any user
 */
export const Roles = {
  // User Account Status
  STATUS_VERIFIED: 'CitizenId/Status/Verified',
  STATUS_BANNED: 'CitizenId/Status/Banned',
  
  // Account Types
  ACCOUNT_TYPE_ORGANIZATION: 'CitizenId/AccountType/Organization',
  ACCOUNT_TYPE_CITIZEN: 'CitizenId/AccountType/Citizen',
  
  // Privileged Roles
  ACCOUNT_ROLE_PARTNER: 'CitizenId/AccountRole/Partner',
  ACCOUNT_ROLE_INTEGRATOR: 'CitizenId/AccountRole/Integrator',
  
  // Internal Roles (reserved for Citizen iD staff - should not be used in applications)
  INTERNAL_SYSTEM: 'CitizenId/Internal/InternalSystem',
  INTERNAL_SUPER_ADMIN: 'CitizenId/Internal/SuperAdmin',
  INTERNAL_ADMIN: 'CitizenId/Internal/Admin',
  INTERNAL_MODERATOR: 'CitizenId/Internal/Moderator',
} as const;

/**
 * Type for role values
 */
export type Role = typeof Roles[keyof typeof Roles];

/**
 * Legacy role format (for backward compatibility)
 * These are the old format roles that may still appear in tokens
 */
export const LegacyRoles = {
  INTEGRATOR: 'CitizenId.Integrator',
  CITIZEN: 'CitizenId.AccountType.Citizen',
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
