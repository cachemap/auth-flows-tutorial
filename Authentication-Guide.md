# Authentication for TypeScript Developers
## A Comprehensive Guide to JWT, OIDC, and Modern Auth Strategies

### Quick Reference

| Scenario | Recommendation | Section |
|----------|---------------|---------|
| **Understanding JWT/OIDC/OAuth** | Start here | [Core Concepts](sections/01-core-concepts.md) |
| **Need working code now** | Copy & adapt | [Code Samples](sections/02-code-samples.md) |
| **Building a new app** | Full-featured framework | [Better Auth](sections/03-better-auth.md) |
| **Comparing approaches** | Pros/cons analysis | [Implementation Types](sections/04-implementation-types.md) |
| **Hardening your app** | Checklists & patterns | [Security Best Practices](sections/05-security-best-practices.md) |
| **Choosing a solution** | Decision matrix | [Choosing the Right Approach](sections/06-choosing-the-right-approach.md) |


## Table of Contents

### 1. [Core Concepts](sections/01-core-concepts.md)
Foundational knowledge for understanding authentication systems.
- What is Authentication vs Authorization?
- JSON Web Tokens (JWT) — structure, flow, and key considerations
- OpenID Connect (OIDC) — identity layer, authorization code flow, tokens
- OAuth 2.0 — scopes and authorization framework

### 2. [Code Samples](sections/02-code-samples.md)
Practical TypeScript implementations using popular open-source libraries.
- Basic JWT implementation with `jsonwebtoken`
- Express middleware for protected routes & role-based access
- OIDC integration with `openid-client` (Google example)

### 3. [Better Auth](sections/03-better-auth.md)
Deep dive into Theo Browne's recommended TypeScript-first auth framework.
- Why Better Auth — type safety, self-hosted, batteries included
- Configuration — database adapters, OAuth providers, sessions
- Next.js integration — server & client setup
- React component usage
- Two-Factor Authentication (2FA) plugin

### 4. [Implementation Types](sections/04-implementation-types.md)
Comparing different architectural approaches to authentication.
- Third-Party Auth Services (Clerk, Auth0, Firebase Auth)
- Self-Hosted Solutions (Better Auth, Lucia, Keycloak)
- Custom-Built Systems — when and why (almost never)
- Session-Based vs Token-Based Authentication
- Hybrid approach (recommended)
- Magic Link (Passwordless) Authentication — flow, implementation, and security

### 5. [Security Best Practices](sections/05-security-best-practices.md)
Essential security patterns every developer should follow.
- Token security — storage, httpOnly cookies, XSS prevention
- Password security — Argon2id hashing
- Rate limiting for auth endpoints
- Token refresh strategy with Axios interceptors

### 6. [Choosing the Right Approach](sections/06-choosing-the-right-approach.md)
Decision framework for selecting the right auth solution.
- Decision flowchart by team size, budget, and compliance needs
- Quick decision matrix for common scenarios
- Conclusion and further reading

---