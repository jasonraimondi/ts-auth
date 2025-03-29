import type { AuthUserEntity, AuthUserIdentifier } from "../entities/auth_user_entity.ts";

export interface AuthUserRepositoryInterface {
  /**
   * Retrieve user by email, username, or ID.
   * Must return null/throw if user not found.
   * Return type should match AuthUserEntity structure.
   * @param id - The identifier of the user.
   * @returns A promise that resolves to an AuthUserEntity.
   */
  getByIdentifier<AuthUser extends AuthUserEntity = AuthUserEntity>(
    id: AuthUserIdentifier,
  ): Promise<AuthUser>;

  /**
   * Increment user's tokenVersion to invalidate all existing tokens.
   * Called during logoutAll operations.
   * @param id - The identifier of the user.
   * @returns A promise that resolves when the operation is complete.
   */
  incrementTokenVersion(id: AuthUserIdentifier): Promise<void>;

  /**
   * Optional method to track login activity.
   * Update lastLoginAt timestamp and store IP address.
   * @param id - The identifier of the user.
   * @param createdIP - The IP address from which the login was created.
   * @returns A promise that resolves when the operation is complete.
   */
  incrementLastLogin?(id: AuthUserIdentifier, createdIP: string): Promise<void>;
}
