import { v7 as uuidv7 } from "uuid";

import type { TokenRepositoryInterface } from "./repositories/token_repository.ts";
import type { AccessTokenPayload, JwtServiceInterface } from "./services/jwt_service.ts";
import type { PasswordServiceInterface } from "./services/password_service.ts";
import type { AuthUserRepositoryInterface } from "./repositories/auth_user_repository.ts";
import type { AuthUserEntity, AuthUserIdentifier } from "./entities/auth_user_entity.ts";
import type { SessionTokenEntity } from "./entities/token_entity.ts";

export interface LoginResponse {
  user: AuthUserEntity;
  token: string;
  tokenExpiresAt: Date;
  tokenTTL: number;
}

export interface LoginInput {
  identifier: string;
  password: string;
  ipAddr: string;
  rememberMe?: boolean;
}

export interface AuthenticationServerConfig {
  accessTokenTTL: number;
  accessTokenRememberMeTTL: number;
}

export class AuthenticationServer {
  protected readonly config: AuthenticationServerConfig;

  constructor(
    protected readonly userRepository: AuthUserRepositoryInterface,
    protected readonly tokenRepository: TokenRepositoryInterface,
    protected readonly jwtService: JwtServiceInterface,
    protected readonly passwordService: PasswordServiceInterface,
    config: Partial<AuthenticationServerConfig>,
  ) {
    this.config = {
      accessTokenTTL: 60 * 60 * 1000,
      accessTokenRememberMeTTL: 60 * 60 * 24 * 30 * 1000,
      ...config,
    };
  }

  async login(loginInput: LoginInput): Promise<LoginResponse> {
    const user = await this.userRepository.getByIdentifier(
      loginInput.identifier,
    );

    if (!user) throw new Error("User not found");

    if (!user.passwordHash) throw new Error("User has no password");

    const success = await this.passwordService.verify(
      loginInput.password,
      user.passwordHash,
    );

    if (!success) throw new Error("Invalid password");

    await this.userRepository.incrementLastLogin?.(
      loginInput.identifier,
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
      tokenVersion: user.tokenVersion,
      userIdentifier: user.identifier,
    };

    const tokenJWT = this.jwtService.sign({
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

  async parse(token: string): Promise<AccessTokenPayload | null> {
    const payload = await this.jwtService.decode<AccessTokenPayload>(token);

    if (!this.isAccessTokenPayload(payload)) return null;

    return payload;
  }

  async verify(token: string): Promise<boolean> {
    const { success } = await this.verifyWithPayload(token);
    return success;
  }

  async verifyWithPayload(token: string): Promise<VerifyWithPayloadResponse> {
    const payload = await this.jwtService.verify<AccessTokenPayload>(token);
    if (!this.isAccessTokenPayload(payload)) return { success: false };

    const tokenEntity = await this.tokenRepository.getToken(payload.token);
    const user = await this.userRepository.getByIdentifier(
      payload.userIdentifier,
    );

    if (tokenEntity.expiresAt < new Date()) return { success: false };

    const success = payload.tokenVersion === tokenEntity.tokenVersion &&
      payload.tokenVersion === user.tokenVersion;

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

type VerifyWithPayloadResponse = {
  success: false;
  user?: AuthUserEntity;
  payload?: AccessTokenPayload;
} | {
  success: true;
  user: AuthUserEntity;
  payload: AccessTokenPayload;
};
