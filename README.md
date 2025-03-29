# Authentication Server

A JWT-based authentication system with session management.

## Core Components

- `AuthenticationServer`: Main authentication logic
- `JwtService`: JWT token handling
- `PasswordService`: Password hashing and verification
- Repository interfaces for users and tokens

## Installation

```bash
pnpm dlx jsr add @jmondi/auth
deno add jsr:@jmondi/auth
```

## Usage

### Basic Setup

```typescript
import { 
  AuthenticationServer, 
  JwtService, 
  BcryptPasswordService 
} from '@your-org/auth-server';

// Create services
const jwtService = new JwtService({ 
  secret: process.env.JWT_SECRET 
});

const passwordService = new BcryptPasswordService(10);

// Initialize with repositories
const authServer = new AuthenticationServer(
  userRepository,
  tokenRepository,
  jwtService,
  passwordService,
  { 
    accessTokenTTL: 3600000, // 1 hour
    accessTokenRememberMeTTL: 2592000000 // 30 days
  }
);
```

### Login

```typescript
// Login with identifier/password
const loginResult = await authServer.login({
  identifier: "user@example.com",
  password: "securepassword123",
  ipAddr: "192.168.1.1",
  rememberMe: true
});

// Login with user object
const loginResult = await authServer.login({
  user: userObject,
  ipAddr: "192.168.1.1"
});

// Response
const { user, token, tokenExpiresAt, tokenTTL } = loginResult;
```

### Token Verification

```typescript
// Verify token
const isValid = await authServer.verify(token);

// Get payload with verification
const { success, user, payload } = await authServer.verifyWithPayload(token);
if (success) {
  // User is authenticated
}

// Parse token without verification
const payload = await authServer.parse(token);
```

### Session Management

```typescript
// Logout (revoke single token)
await authServer.logout(token);

// Logout all sessions
await authServer.logoutAll(userId);

// Parse Authorization header
const token = AuthenticationServer.parseAuthorizationHeader(
  request.headers.authorization
);
```

## Implementing Repositories

Create custom repositories that implement the required interfaces:

```typescript
interface AuthUserRepositoryInterface {
  // Retrieve user by email, username, or ID
  // Must return null/throw if user not found
  // Return type should match AuthUserEntity structure
  getByIdentifier<T extends AuthUserEntity>(id: string): Promise<T>;

  // Increment user's tokenVersion to invalidate all existing tokens
  // Called during logoutAll operations
  incrementTokenVersion(id: string): Promise<void>;

  // Optional method to track login activity
  // Update lastLoginAt timestamp and store IP address
  incrementLastLogin(id: string, ip: string): Promise<void>;
}

interface TokenRepositoryInterface {
  // Retrieve token entity by token string
  // Should throw/return null if token doesn't exist
  // Used during token verification
  getToken(token: string): Promise<TokenEntity>;

  // Store new token in database
  // Called during login to create session
  persistToken(tokenEntity: TokenEntity): Promise<void>;

  // Mark token as revoked or delete it
  // Called during logout operations
  revokeToken(token: string): Promise<void>;
}
```
