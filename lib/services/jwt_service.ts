import jsonwebtoken, { type JwtPayload } from "jsonwebtoken";
import type { AuthUserIdentifier } from "../entities/auth_user_entity.ts";

export type JWT = JwtPayload & {
  token: string;
  userIdentifier?: AuthUserIdentifier;
  expiresAt?: Date | number;
};

export interface JwtServiceInterface {
  sign(payload: JWT): string;
  verify<T = JwtPayload | string | null>(token: string): T;
  decode<T = JwtPayload | string | null>(token: string): T;
}

export type JwtConfig = {
  secret: string;
  issuer?: string;
};

export class JwtService implements JwtServiceInterface {
  constructor(private readonly config: JwtConfig) {
  }

  sign(jwt: JWT): string {
    const { userId = undefined, expiresAt = undefined, ...payload } = jwt;
    const now = this.roundToSeconds(new Date());

    return jsonwebtoken.sign({
      iss: this.config.issuer,
      sub: userId,
      aud: undefined,
      nbf: now,
      iat: now,
      ...payload,
      exp: expiresAt ? this.roundToSeconds(expiresAt) : undefined,
      expiresAt,
    }, this.config.secret);
  }

  verify<T = string | JwtPayload | null>(token: string): T {
    return jsonwebtoken.verify(token, this.config.secret) as T;
  }

  decode<T = string | JwtPayload | null>(token: string): T {
    return jsonwebtoken.decode(token) as T;
  }

  protected roundToSeconds(ms: Date | number): number {
    if (ms instanceof Date) ms = ms.getTime();
    return Math.ceil(ms / 1000);
  }
}

export type AccessTokenPayload = JWT & {
  id: string;
  tokenVersion: number;
  expiresAt: Date | number;
};

export class AccessTokenJwtService extends JwtService {
  sign(payload: AccessTokenPayload): string {
    return super.sign(payload);
  }
}
