import { AuthUserIdentifier } from "./auth_user_entity.ts";

export interface TokenEntity {
  token: string;
  tokenType: string;
  loginIP?: string;
  userIdentifier: AuthUserIdentifier;
  createdAt: Date;
  expiresAt: Date;
}

export interface SessionTokenEntity extends TokenEntity {
  tokenType: "session";
  loginIP: string;
}

export interface AccessTokenEntity extends TokenEntity {
  tokenType: "access_token";
  loginIP: string;
}
