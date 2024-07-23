export type AuthUserIdentifier = string | number;

export interface AuthUserEntity {
  id: AuthUserIdentifier;
  passwordHash?: string | null;
  tokenVersion: number;
  [key: string]: unknown;
}
