import type { AuthUserEntity, AuthUserIdentifier } from "../entities/auth_user_entity.ts";

export interface AuthUserRepositoryInterface {
  getByIdentifier<AuthUser extends AuthUserEntity = AuthUserEntity>(
    id: AuthUserIdentifier,
  ): Promise<AuthUser>;
  incrementTokenVersion(id: AuthUserIdentifier): Promise<void>;
  incrementLastLogin?(id: AuthUserIdentifier, createdIP: string): Promise<void>;
}
