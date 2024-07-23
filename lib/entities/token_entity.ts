export interface TokenEntity {
  token: string;
  tokenType: string;
  tokenVersion?: number;
  loginIP?: string;
  createdAt: Date;
  expiresAt: Date;
}

export interface SessionTokenEntity extends TokenEntity {
  tokenType: "session";
  tokenVersion: number;
  loginIP: string;
}

export interface AccessTokenEntity extends TokenEntity {
  tokenType: "access_token";
  tokenVersion: number;
  loginIP: string;
}
