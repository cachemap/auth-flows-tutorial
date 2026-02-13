# Better Auth (Theo Browne's Recommendation)

[Better Auth](https://www.better-auth.com/) is a TypeScript-first authentication framework that Theo Browne recommends for its excellent developer experience, type safety, and framework-agnostic design. It's self-hosted, giving you full control over your auth system.

## Why Better Auth?

- 🔷 **TypeScript-first** - Full type safety throughout
- 🏠 **Self-hosted** - You own your data
- 🔌 **Database adapters** - Works with Prisma, Drizzle, MongoDB, etc.
- 📦 **Batteries included** - Email/password, OAuth, 2FA, magic links
- ⚡ **Framework agnostic** - Works with Next.js, Express, Hono, etc.

## Installation & Setup

```bash
npm install better-auth
```

## Basic Configuration

```typescript
// src/lib/auth.ts
import { betterAuth } from 'better-auth';
import { prismaAdapter } from 'better-auth/adapters/prisma';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export const auth = betterAuth({
  // Database adapter
  database: prismaAdapter(prisma, {
    provider: 'postgresql', // or 'mysql', 'sqlite'
  }),

  // Email/password authentication
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 8,
    requireEmailVerification: true,
  },

  // Session configuration
  session: {
    expiresIn: 60 * 60 * 24 * 7, // 7 days
    updateAge: 60 * 60 * 24,     // Update session every 24 hours
    cookieCache: {
      enabled: true,
      maxAge: 60 * 5, // Cache for 5 minutes
    },
  },

  // OAuth providers
  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    },
    github: {
      clientId: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    },
    discord: {
      clientId: process.env.DISCORD_CLIENT_ID!,
      clientSecret: process.env.DISCORD_CLIENT_SECRET!,
    },
  },

  // Advanced options
  advanced: {
    generateId: () => crypto.randomUUID(),
  },
});

// Export the type for client usage
export type Auth = typeof auth;
```

## Next.js Integration

```typescript
// app/api/auth/[...all]/route.ts
import { auth } from '@/lib/auth';
import { toNextJsHandler } from 'better-auth/next-js';

export const { GET, POST } = toNextJsHandler(auth);
```

## Client-Side Setup

```typescript
// src/lib/auth-client.ts
import { createAuthClient } from 'better-auth/react';

export const authClient = createAuthClient({
  baseURL: process.env.NEXT_PUBLIC_APP_URL!,
});

// Export typed hooks
export const { 
  useSession,
  signIn,
  signOut,
  signUp,
} = authClient;
```

## Usage in React Components

```tsx
// components/AuthButton.tsx
'use client';

import { useSession, signIn, signOut } from '@/lib/auth-client';

export function AuthButton() {
  const { data: session, isPending } = useSession();

  if (isPending) {
    return <button disabled>Loading...</button>;
  }

  if (session) {
    return (
      <div className="flex items-center gap-4">
        <img 
          src={session.user.image ?? '/default-avatar.png'} 
          alt={session.user.name}
          className="w-8 h-8 rounded-full"
        />
        <span>{session.user.name}</span>
        <button 
          onClick={() => signOut()}
          className="px-4 py-2 bg-red-500 text-white rounded"
        >
          Sign Out
        </button>
      </div>
    );
  }

  return (
    <div className="flex gap-2">
      <button 
        onClick={() => signIn.social({ provider: 'google' })}
        className="px-4 py-2 bg-blue-500 text-white rounded"
      >
        Sign in with Google
      </button>
      <button 
        onClick={() => signIn.social({ provider: 'github' })}
        className="px-4 py-2 bg-gray-800 text-white rounded"
      >
        Sign in with GitHub
      </button>
    </div>
  );
}
```

## Server-Side Session Access

```typescript
// app/dashboard/page.tsx
import { auth } from '@/lib/auth';
import { headers } from 'next/headers';
import { redirect } from 'next/navigation';

export default async function DashboardPage() {
  const session = await auth.api.getSession({
    headers: headers(),
  });

  if (!session) {
    redirect('/login');
  }

  return (
    <div>
      <h1>Welcome, {session.user.name}!</h1>
      <p>Email: {session.user.email}</p>
    </div>
  );
}
```

## Adding Two-Factor Authentication

```typescript
// src/lib/auth.ts (extended)
import { betterAuth } from 'better-auth';
import { twoFactor } from 'better-auth/plugins';

export const auth = betterAuth({
  // ... other config
  
  plugins: [
    twoFactor({
      issuer: 'Your App Name',
      // TOTP configuration
      totpOptions: {
        period: 30,
        digits: 6,
      },
    }),
  ],
});
```

```tsx
// Client-side 2FA setup
import { authClient } from '@/lib/auth-client';

async function enableTwoFactor() {
  const { data, error } = await authClient.twoFactor.enable({
    password: 'current-password',
  });

  if (data) {
    // Show QR code to user
    const qrCodeUrl = data.totpURI;
    // Store backup codes securely
    const backupCodes = data.backupCodes;
  }
}
```

---

[← Back to Authentication Guide](../Authentication-Guide.md)
