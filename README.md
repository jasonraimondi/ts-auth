# @jmondi/auth

WIP

```ts
import { AuthenticationServer } from "@jmondi/auth";
import { TokenRepository, UserRepository } from "@jmondi/auth";
import { JwtService, PasswordService } from "@jmondi/auth";

const userRepository = new UserRepository();
const tokenRepository = new TokenRepository();

const jwtService = new JwtService();
const passwordService = new PasswordService();

const authServer = new AuthenticationServer(
  userRepository,
  tokenRepository,
  jwtService,
  passwordService,
);

const user = await authServer.login("username", "password");
await authServer.verify("token-token-token");
await authServer.logout("token-token-token");
```
