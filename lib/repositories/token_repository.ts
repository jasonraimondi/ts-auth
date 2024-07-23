import { TokenEntity } from "../entities/token_entity.ts";

export interface TokenRepositoryInterface {
  getToken(token: string): Promise<TokenEntity>;
  persistToken(tokenEntity: TokenEntity): Promise<void>;
  deleteToken(token: string): Promise<void>;
}
