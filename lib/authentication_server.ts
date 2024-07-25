import { TokenRepositoryInterface } from "./repositories/token_repository.ts";
import {
  AccessTokenPayload,
  JwtServiceInterface,
} from "./services/jwt_service.ts";
import { PasswordServiceInterface } from "./services/password_service.ts";
import { AuthUserRepositoryInterface } from "./repositories/auth_user_repository.ts";
import {
  AuthUserEntity,
  AuthUserIdentifier,
} from "./entities/auth_user_entity.ts";
import { SessionTokenEntity } from "./entities/token_entity.ts";

export interface LoginResponse {
  user: AuthUserEntity;
  token: string;
  tokenExpiresAt: Date;
  tokenTTL: number;
}

export interface LoginInput {
  id: string;
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
    const user = await this.userRepository.getByIdentifier(loginInput.id);

    if (!user) throw new Error("User not found");

    if (!user.passwordHash) throw new Error("User has no password");

    const success = await this.passwordService.verify(
      loginInput.password,
      user.passwordHash,
    );

    if (!success) throw new Error("Invalid password");

    await this.userRepository.incrementLastLogin?.(
      loginInput.id,
      loginInput.ipAddr,
    );

    const tokenTTL = loginInput.rememberMe
      ? this.config.accessTokenRememberMeTTL
      : this.config.accessTokenTTL;

    const tokenExpiresAt = new Date(Date.now() + tokenTTL);

    const tokenJWT = this.jwtService.sign({
      expiresAt: tokenExpiresAt,
      id: user.email,
      tokenVersion: user.tokenVersion,
    });

    const tokenEntity: SessionTokenEntity = {
      token: tokenJWT,
      tokenType: "session",
      tokenVersion: user.tokenVersion,
      loginIP: loginInput.ipAddr,
      createdAt: new Date(),
      expiresAt: tokenExpiresAt,
    };

    await this.tokenRepository.persistToken(tokenEntity);

    return { user, token: tokenJWT, tokenTTL, tokenExpiresAt };
  }

  async logoutAll(id: AuthUserIdentifier) {
    await this.userRepository.incrementTokenVersion(id);
  }

  async logout(token: string): Promise<void> {
    await this.tokenRepository.deleteToken(token);
  }

  async verify(token: string): Promise<boolean> {
    const payload = await this.jwtService.verify<AccessTokenPayload>(token);

    if (!this.isAccessTokenPayload(payload)) return false;

    const tokenEntity = await this.tokenRepository.getToken(token);

    if (tokenEntity.expiresAt < new Date()) return false;

    return payload.tokenVersion === tokenEntity.tokenVersion;
  }

  private isAccessTokenPayload(token: unknown): token is AccessTokenPayload {
    if (!token) return false;
    if (typeof token !== "object") return false;
    return "tokenVersion" in token;
  }
}
