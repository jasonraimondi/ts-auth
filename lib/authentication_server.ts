import { v7 as uuidv7 } from "uuid";

import type { TokenRepositoryInterface } from "./repositories/token_repository.ts";
import type { AccessTokenPayload, JwtServiceInterface } from "./services/jwt_service.ts";
import type { PasswordServiceInterface } from "./services/password_service.ts";
import type { AuthUserRepositoryInterface } from "./repositories/auth_user_repository.ts";
import type { AuthUserEntity, AuthUserIdentifier } from "./entities/auth_user_entity.ts";
import type { SessionTokenEntity } from "./entities/token_entity.ts";

export type LoginResponse<TUser extends AuthUserEntity = AuthUserEntity> = {
  user: TUser;
  token: string;
  tokenExpiresAt: Date;
  tokenTTL: number;
};

type PasswordLogin = {
  identifier: string;
  password: string;
};

type UserLogin = {
  user: AuthUserEntity;
};

type Login = (PasswordLogin | UserLogin) & { rememberMe?: boolean };

type LoginWithIP = Login & {
  ipAddr: string;
};

type LoginInput = LoginWithIP;

// export interface LoginInput {
//   identifier: string;
//   password: string;
//   ipAddr: string;
//   rememberMe?: boolean;
// }

export interface AuthenticationServerConfig {
  accessTokenTTL: number;
  accessTokenRememberMeTTL: number;
}

export class AuthenticationServer {
  protected readonly config: AuthenticationServerConfig;

  constructor(
    protected readonly userRepository: AuthUserRepositoryInterface,
    protected readonly tokenRepository: TokenRepositoryInterface,
    public readonly jwtService: JwtServiceInterface,
    public readonly passwordService: PasswordServiceInterface,
    config: Partial<AuthenticationServerConfig>,
  ) {
    this.config = {
      accessTokenTTL: 60 * 60 * 1000,
      accessTokenRememberMeTTL: 60 * 60 * 24 * 30 * 1000,
      ...config,
    };
  }

  static parseAuthorizationHeader(header?: string | null): string | null {
    if (!header) return null;

    const [_tokenType, token = null] = header.split(" ");

    return token;
  }

  async verifyByUserCredentials<AuthUser extends AuthUserEntity = AuthUserEntity>(
    identifier: AuthUserIdentifier,
    passwordAttempt: string,
  ): Promise<{ success: true; user: AuthUser } | { success: false; user?: never }> {
    const user = await this.userRepository.getByIdentifier<AuthUser>(identifier);

    if (!user || !user.passwordHash) return { success: false };

    const success = await this.passwordService.verify(
      passwordAttempt,
      user.passwordHash,
    );

    if (!success) return { success: false };

    return { success, user };
  }

  async login<TUser extends AuthUserEntity = AuthUserEntity>(
    loginInput: LoginInput,
  ): Promise<LoginResponse<TUser>> {
    let user: TUser | undefined = undefined;

    if ("user" in loginInput) {
      user = loginInput.user as TUser;
    } else if ("identifier" in loginInput) {
      const verifyRes = await this.verifyByUserCredentials(loginInput.identifier, loginInput.password);
      if (verifyRes.user) {
        user = verifyRes.user as TUser;
      }
    }

    if (user === undefined) throw new Error("invalid login");

    await this.userRepository.incrementLastLogin?.(
      user.identifier,
      loginInput.ipAddr,
    );

    const tokenTTL = loginInput.rememberMe
      ? this.config.accessTokenRememberMeTTL
      : this.config.accessTokenTTL;

    const tokenExpiresAt = new Date(Date.now() + tokenTTL);

    const tokenEntity: SessionTokenEntity = {
      createdAt: new Date(),
      expiresAt: tokenExpiresAt,
      loginIP: loginInput.ipAddr,
      token: uuidv7(),
      tokenType: "session",
      userIdentifier: user.identifier,
    };

    const tokenJWT = this.jwtService.sign({
      ...this.jwtService.extraTokenFields?.({ user }),

      expiresAt: tokenExpiresAt,
      token: tokenEntity.token,
      tokenVersion: user.tokenVersion,
      userIdentifier: tokenEntity.userIdentifier,
    });

    await this.tokenRepository.persistToken(tokenEntity);

    return { user, token: tokenJWT, tokenTTL, tokenExpiresAt };
  }

  async logoutAll(id: AuthUserIdentifier) {
    await this.userRepository.incrementTokenVersion(id);
  }

  async logout(token: string): Promise<void> {
    await this.tokenRepository.revokeToken(token);
  }

  async parse<Payload extends AccessTokenPayload = AccessTokenPayload>(
    token: string,
  ): Promise<Payload | null> {
    const payload = await this.jwtService.decode<AccessTokenPayload>(token);
    if (!this.isAccessTokenPayload(payload)) return null;
    return payload as Payload;
  }

  async verify(token: string): Promise<boolean> {
    const { success } = await this.verifyWithPayload(token);
    return success;
  }

  async verifyWithPayload<
    AuthUser extends AuthUserEntity = AuthUserEntity,
    Payload extends AccessTokenPayload = AccessTokenPayload,
  >(token: string): Promise<VerifyWithPayloadResponse<AuthUser, Payload>> {
    const payload = await this.jwtService.verify<AccessTokenPayload>(token);
    if (!this.isAccessTokenPayload(payload)) return { success: false };

    const tokenEntity = await this.tokenRepository.getToken(payload.token);
    const user = await this.userRepository.getByIdentifier<AuthUser>(
      payload.userIdentifier,
    );

    if (tokenEntity.expiresAt < new Date()) return { success: false };

    const success = payload.tokenVersion === user.tokenVersion;

    return { success, user, payload };
  }

  private isAccessTokenPayload(
    payload: unknown,
  ): payload is AccessTokenPayload {
    if (!payload) return false;
    if (typeof payload !== "object") return false;
    return "tokenVersion" in payload;
  }
}

type VerifyWithPayloadResponse<
  AuthUser extends AuthUserEntity,
  Payload extends AccessTokenPayload,
> = {
  success: false;
  user?: AuthUser;
  payload?: Payload;
} | {
  success: true;
  user: AuthUser;
  payload: Payload;
};
