import type { TokenEntity } from "../entities/token_entity.ts";

export interface TokenRepositoryInterface {
  /**
   * Retrieve token entity by token string.
   * Should throw/return null if token doesn't exist.
   * Used during token verification.
   * @param token - The token string.
   * @returns A promise that resolves to a TokenEntity.
   */
  getToken(token: string): Promise<TokenEntity>;

  /**
   * Store new token in database.
   * Called during login to create session.
   * @param tokenEntity - The token entity to persist.
   * @returns A promise that resolves when the operation is complete.
   */
  persistToken(tokenEntity: TokenEntity): Promise<void>;

  /**
   * Mark token as revoked or delete it.
   * Called during logout operations.
   * @param token - The token string to revoke.
   * @returns A promise that resolves when the operation is complete.
   */
  revokeToken(token: string): Promise<void>;
}
