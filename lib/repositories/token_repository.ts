import type { TokenEntity } from "../entities/token_entity.ts";

export interface TokenRepositoryInterface {
  getToken(token: string): Promise<TokenEntity>;
  persistToken(tokenEntity: TokenEntity): Promise<void>;
  revokeToken(token: string): Promise<void>;
}
