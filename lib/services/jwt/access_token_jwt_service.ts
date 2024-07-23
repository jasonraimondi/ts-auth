import { JWT, JwtService } from "./jwt_service.ts";

export type AccessTokenPayload = JWT & {
  id: string;
  tokenVersion: number;
  expiresAt: Date | number;
};

export class AccessTokenJwtService extends JwtService {
  sign(payload: AccessTokenPayload): string {
    return super.sign(payload);
  }
}
