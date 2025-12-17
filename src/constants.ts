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
 * Prefix for custom user claims
 */
export const CUSTOM_CLAIM_PREFIX = 'urn:user:';

/**
 * Suffix for avatar URL claims
 */
export const AVATAR_URL_SUFFIX = ':avatar:url';

/**
 * Custom profile claim keys for avatar URLs
 */
export const AvatarClaimKeys = {
  RSI: `${CUSTOM_CLAIM_PREFIX}rsi${AVATAR_URL_SUFFIX}`,
  DISCORD: `${CUSTOM_CLAIM_PREFIX}discord${AVATAR_URL_SUFFIX}`,
  TWITCH: `${CUSTOM_CLAIM_PREFIX}twitch${AVATAR_URL_SUFFIX}`,
  GOOGLE: `${CUSTOM_CLAIM_PREFIX}google${AVATAR_URL_SUFFIX}`,
} as const;

/**
 * Array of all avatar claim keys for easy iteration
 */
export const ALL_AVATAR_CLAIM_KEYS = Object.values(AvatarClaimKeys);

/**
 * Google profile custom claim keys
 * Reference: https://docs.citizenid.space/integrator-guide/oauth2/scopes-claims
 */
export const GoogleClaimKeys = {
  AVATAR_URL: `${CUSTOM_CLAIM_PREFIX}google${AVATAR_URL_SUFFIX}`,
  EMAIL: `${CUSTOM_CLAIM_PREFIX}google:email`,
  NAME: `${CUSTOM_CLAIM_PREFIX}google:name`,
  ACCOUNT_ID: `${CUSTOM_CLAIM_PREFIX}google:accountId`,
} as const;

/**
 * Twitch profile custom claim keys
 * Reference: https://docs.citizenid.space/integrator-guide/oauth2/scopes-claims
 */
export const TwitchClaimKeys = {
  AVATAR_URL: `${CUSTOM_CLAIM_PREFIX}twitch${AVATAR_URL_SUFFIX}`,
  EMAIL: `${CUSTOM_CLAIM_PREFIX}twitch:email`,
  USERNAME: `${CUSTOM_CLAIM_PREFIX}twitch:username`,
  ACCOUNT_ID: `${CUSTOM_CLAIM_PREFIX}twitch:accountId`,
} as const;

/**
 * Discord profile custom claim keys
 * Reference: https://docs.citizenid.space/integrator-guide/oauth2/scopes-claims
 */
export const DiscordClaimKeys = {
  AVATAR_URL: `${CUSTOM_CLAIM_PREFIX}discord${AVATAR_URL_SUFFIX}`,
  USERNAME: `${CUSTOM_CLAIM_PREFIX}discord:username`,
  ACCOUNT_ID: `${CUSTOM_CLAIM_PREFIX}discord:accountId`,
  SCOPES: `${CUSTOM_CLAIM_PREFIX}discord:scopes`,
} as const;

/**
 * RSI profile custom claim keys
 * Reference: https://docs.citizenid.space/integrator-guide/oauth2/scopes-claims
 */
export const RSIClaimKeys = {
  AVATAR_URL: `${CUSTOM_CLAIM_PREFIX}rsi${AVATAR_URL_SUFFIX}`,
  USERNAME: `${CUSTOM_CLAIM_PREFIX}rsi:username`,
  ENLISTED_AT: `${CUSTOM_CLAIM_PREFIX}rsi:enlistedAt`,
  CITIZEN_ID: `${CUSTOM_CLAIM_PREFIX}rsi:citizenId`,
  SPECTRUM_ID: `${CUSTOM_CLAIM_PREFIX}rsi:spectrumId`,
} as const;

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
  },
  DEVELOPMENT: {
    AUTHORITY: 'https://dev.citizenid.space',
  },
} as const;

// Endpoint path suffixes appended to the selected authority
export const EndpointPaths = {
  AUTHORIZATION: '/connect/authorize',
  TOKEN: '/connect/token',
  USERINFO: '/connect/userinfo',
  REVOKE: '/connect/revoke',
  DISCOVERY: '/.well-known/openid-configuration',
} as const;

/**
 * Helper function to get endpoints for a given authority
 */
export function getEndpoints(authority: string = Endpoints.PRODUCTION.AUTHORITY) {
  return {
    AUTHORITY: authority,
    AUTHORIZATION: `${authority}${EndpointPaths.AUTHORIZATION}`,
    TOKEN: `${authority}${EndpointPaths.TOKEN}`,
    USERINFO: `${authority}${EndpointPaths.USERINFO}`,
    REVOKE: `${authority}${EndpointPaths.REVOKE}`,
    DISCOVERY: `${authority}${EndpointPaths.DISCOVERY}`,
  };
}
