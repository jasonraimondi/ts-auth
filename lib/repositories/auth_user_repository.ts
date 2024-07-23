import {
  AuthUserEntity,
  AuthUserIdentifier,
} from "../entities/auth_user_entity.ts";

export interface AuthUserRepositoryInterface {
  getByIdentifier(id: AuthUserIdentifier): Promise<AuthUserEntity>;
  incrementTokenVersion(id: AuthUserIdentifier): Promise<void>;
  incrementLastLogin?(id: AuthUserIdentifier, createdIP: string): Promise<void>;
}
