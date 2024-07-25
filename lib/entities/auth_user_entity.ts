export type AuthUserIdentifier = string | number;

export interface AuthUserEntity {
  identifier: AuthUserIdentifier;
  passwordHash?: string | null;
  tokenVersion: number;
  [key: string]: unknown;
}
