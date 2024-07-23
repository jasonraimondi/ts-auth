import jsonwebtoken, { type JwtPayload } from "jsonwebtoken";

export type JWT = JwtPayload & {
  id?: string;
  expiresAt?: Date | number;
};

export interface JwtServiceInterface {
  sign(payload: Record<string, unknown>): string;
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
    const { id = undefined, expiresAt = undefined, ...payload } = jwt;
    const now = this.roundToSeconds(new Date());

    return jsonwebtoken.sign({
      iss: this.config.issuer,
      sub: id,
      aud: undefined,
      exp: expiresAt ? this.roundToSeconds(expiresAt) : undefined,
      nbf: now,
      iat: now,
      ...payload,
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
