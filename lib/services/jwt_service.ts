import jsonwebtoken, { type JwtPayload } from "jsonwebtoken";
import type { AuthUserEntity, AuthUserIdentifier } from "../entities/auth_user_entity.ts";

export type JWT = JwtPayload & {
  token: string;
  userIdentifier?: AuthUserIdentifier;
  expiresAt?: Date | number;
};

export type ExtraAccessTokenFieldArgs = {
  user?: AuthUserEntity | null;
};

type Allowed = string | number | boolean | undefined | null;

export type ExtraAccessTokenFieldsResponse = Record<
  string,
  Allowed | Allowed[]
>;

export interface JwtServiceInterface {
  sign(payload: JWT): string;
  verify<T = JwtPayload | string | null>(token: string): T;
  decode<T = JwtPayload | string | null>(token: string): T;
  extraTokenFields?(
    params: ExtraAccessTokenFieldArgs,
  ): ExtraAccessTokenFieldsResponse | Promise<ExtraAccessTokenFieldsResponse>;
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
    return Math.floor(ms / 1000);
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
