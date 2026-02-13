# Code Samples

## Typical Solutions with Open Source Libraries

### 1. Basic JWT Implementation with `jsonwebtoken`

```bash
npm install jsonwebtoken @types/jsonwebtoken
```

```typescript
// src/auth/jwt.ts
import jwt, { SignOptions, JwtPayload } from 'jsonwebtoken';

// Environment variables (use dotenv or similar)
const JWT_SECRET = process.env.JWT_SECRET!;
const JWT_EXPIRES_IN = '15m';
const JWT_REFRESH_EXPIRES_IN = '7d';

interface TokenPayload {
  userId: string;
  email: string;
  roles: string[];
}

interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

/**
 * Generate access and refresh tokens for a user
 */
export function generateTokens(payload: TokenPayload): AuthTokens {
  const accessToken = jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    issuer: 'your-app',
    audience: 'your-app-users',
  });

  const refreshToken = jwt.sign(
    { userId: payload.userId, type: 'refresh' },
    JWT_SECRET,
    { expiresIn: JWT_REFRESH_EXPIRES_IN }
  );

  return { accessToken, refreshToken };
}

/**
 * Verify and decode an access token
 */
export function verifyAccessToken(token: string): TokenPayload | null {
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: 'your-app',
      audience: 'your-app-users',
    }) as TokenPayload & JwtPayload;

    return {
      userId: decoded.userId,
      email: decoded.email,
      roles: decoded.roles,
    };
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      console.error('Token expired');
    } else if (error instanceof jwt.JsonWebTokenError) {
      console.error('Invalid token');
    }
    return null;
  }
}

/**
 * Verify refresh token and return new token pair
 */
export function refreshTokens(refreshToken: string): AuthTokens | null {
  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET) as JwtPayload & {
      userId: string;
      type: string;
    };

    if (decoded.type !== 'refresh') {
      return null;
    }

    // In production, fetch fresh user data from database
    // const user = await db.user.findUnique({ where: { id: decoded.userId } });
    
    return generateTokens({
      userId: decoded.userId,
      email: 'user@example.com', // Fetch from DB
      roles: ['user'],           // Fetch from DB
    });
  } catch {
    return null;
  }
}
```

### 2. Express Middleware for Protected Routes

```typescript
// src/middleware/auth.ts
import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, TokenPayload } from '../auth/jwt';

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload;
    }
  }
}

/**
 * Middleware to require authentication
 */
export function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing authorization header' });
    return;
  }

  const token = authHeader.slice(7); // Remove 'Bearer '
  const payload = verifyAccessToken(token);

  if (!payload) {
    res.status(401).json({ error: 'Invalid or expired token' });
    return;
  }

  req.user = payload;
  next();
}

/**
 * Middleware to require specific roles
 */
export function requireRoles(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Not authenticated' });
      return;
    }

    const hasRole = req.user.roles.some(role => allowedRoles.includes(role));

    if (!hasRole) {
      res.status(403).json({ error: 'Insufficient permissions' });
      return;
    }

    next();
  };
}
```

### 3. OIDC with `openid-client`

```bash
npm install openid-client
```

```typescript
// src/auth/oidc.ts
import { Issuer, Client, generators, TokenSet } from 'openid-client';

let googleClient: Client;

/**
 * Initialize the OIDC client (call once at app startup)
 */
export async function initializeOIDC(): Promise<void> {
  // Discover Google's OIDC configuration
  const googleIssuer = await Issuer.discover(
    'https://accounts.google.com'
  );

  console.log('Discovered issuer:', googleIssuer.issuer);

  googleClient = new googleIssuer.Client({
    client_id: process.env.GOOGLE_CLIENT_ID!,
    client_secret: process.env.GOOGLE_CLIENT_SECRET!,
    redirect_uris: [process.env.GOOGLE_REDIRECT_URI!],
    response_types: ['code'],
  });
}

/**
 * Generate the authorization URL to redirect users to
 */
export function getAuthorizationUrl(): { url: string; state: string; nonce: string } {
  const state = generators.state();
  const nonce = generators.nonce();
  const codeVerifier = generators.codeVerifier();
  const codeChallenge = generators.codeChallenge(codeVerifier);

  const url = googleClient.authorizationUrl({
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  // Store state, nonce, codeVerifier in session for validation
  return { url, state, nonce };
}

interface OIDCUser {
  sub: string;
  email: string;
  emailVerified: boolean;
  name: string;
  picture?: string;
}

/**
 * Handle the callback from the identity provider
 */
export async function handleCallback(
  callbackUrl: string,
  expectedState: string,
  expectedNonce: string,
  codeVerifier: string
): Promise<{ user: OIDCUser; tokens: TokenSet }> {
  const params = googleClient.callbackParams(callbackUrl);

  const tokenSet = await googleClient.callback(
    process.env.GOOGLE_REDIRECT_URI!,
    params,
    {
      state: expectedState,
      nonce: expectedNonce,
      code_verifier: codeVerifier,
    }
  );

  // Validate and decode the ID token
  const claims = tokenSet.claims();

  return {
    user: {
      sub: claims.sub,
      email: claims.email!,
      emailVerified: claims.email_verified ?? false,
      name: claims.name!,
      picture: claims.picture,
    },
    tokens: tokenSet,
  };
}
```

---

[← Back to Authentication Guide](../Authentication-Guide.md)
