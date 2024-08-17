# @jmondi/auth

## Project Overview

This project implements a robust authentication system using TypeScript. It provides functionality for user login,
logout, token management, and password hashing. The system is designed to be flexible and extensible, allowing for easy
integration into various applications.

## Key Components

1. **AuthenticationServer**: The main class that orchestrates the authentication process.
2. **Repositories**: Interfaces for user and token storage.
3. **Services**: JWT (JSON Web Token) and password handling services.
4. **Entities**: Definitions for user and token data structures.

## How to Use

### Setting Up

1. Import the necessary components:
   ```typescript
   import { AuthenticationServer, JwtService, BcryptPasswordService } from './lib';
   ```

2. Implement the required repositories:
    - `AuthUserRepositoryInterface`
    - `TokenRepositoryInterface`

3. Configure the services:
   ```typescript
   const jwtService = new JwtService({ secret: 'your-secret-key' });
   const passwordService = new BcryptPasswordService();
   ```

4. Initialize the AuthenticationServer:
   ```typescript
   const authServer = new AuthenticationServer(
     userRepository,
     tokenRepository,
     jwtService,
     passwordService,
     { accessTokenTTL: 3600000 } // 1 hour
   );
   ```

### Authentication Flow

1. **Login**:
   ```typescript
   const loginResponse = await authServer.login({
     identifier: 'user@example.com',
     password: 'password123',
     ipAddr: '127.0.0.1',
     rememberMe: true
   });
   ```

2. **Verify Token**:
   ```typescript
   const isValid = await authServer.verify(token);
   ```

3. **Logout**:
   ```typescript
   await authServer.logout(token);
   ```

4. **Logout All Sessions**:
   ```typescript
   await authServer.logoutAll(userId);
   ```
