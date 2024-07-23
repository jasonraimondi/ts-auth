import bcrypt from "bcryptjs";

export interface PasswordServiceInterface {
  hash(password: string): Promise<string>;

  verify(attempt: string, hashedPassword: string): Promise<boolean>;
}

export class BcryptPasswordService implements PasswordServiceInterface {
  protected saltRounds: number;

  constructor(saltRounds: number = 10) {
    this.saltRounds = saltRounds;
  }

  async hash(password: string): Promise<string> {
    return bcrypt.hash(password, this.saltRounds);
  }

  async verify(
    attempt: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(attempt, hashedPassword);
  }
}

export function parseAuthorizationHeader(
  header?: string | null,
): string | null {
  if (!header) return null;

  const [_tokenType, token = null] = header.split(" ");

  return token;
}
