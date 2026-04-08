# CarKeys

*Grab your keys. You're not going anywhere without them.*

Unified credential vault and device registry. One secure keychain for every login, API token, passkey, and device across The BlackRoad.

## The Ride

Grab your CarKeys. Every login, every token, every device — one keychain, always fresh. Rotate a key? It updates everywhere. Add a new device? Trusted in seconds. You're not going anywhere without them, and you'll never lose them.

## What It Does

Master credential manager that handles authentication, API key storage, device trust scoring, and session management across all 18 BlackRoad products. CarKeys is the ignition — nothing starts without it.

## Integrations

| Service | Role |
|---------|------|
| **Clerk** | Identity provider — user auth, SSO, MFA, session management |
| **Cloudflare D1** | Credential metadata, device registry, rotation history |
| **Cloudflare KV** | Session token cache, fast auth lookups |
| **Stripe** | Subscription tier lookup for access control |
| **RoadChain** | Immutable audit log of every key use, rotation, and revocation |
| **Ollama** | Local agent identity tokens for Pi fleet authentication |

## Vault Structure

```
CarKeys Vault
├── Identities       → Clerk SSO sessions + passkeys
├── API Keys         → Per-product keys with scoped permissions
├── Device Registry  → Trusted devices with fingerprint + trust score
├── Guest Keys       → Time-limited tokens for contractors or agents
├── Team Profiles    → Scoped access for family or org members
└── Audit Log        → Every event RoadChain-stamped
```

## Features

- Single sign-on across all 18 BlackRoad products via Clerk
- API key generation with configurable scopes and expiry
- Automatic key rotation on schedule or on demand
- Device fingerprinting and trust scoring (0–100)
- Family and team profiles with granular permission scoping
- Time-limited guest keys for contractors, collaborators, or AI agents
- Zero-knowledge architecture — credentials encrypted on-device before storage
- Revocation dashboard — invalidate any key or session in one click
- RoadChain-stamped audit trail for every credential event
- Emergency lockdown — freeze all sessions with one tap

## Trust Score System

```
Device Score = base(OS + browser) + history(logins) + behavior(patterns) - risk(anomalies)

≥ 80 → Trusted: full access
50–79 → Verified: standard access, MFA required for sensitive ops
< 50 → Untrusted: read-only, manual review required
```

## Status

**LIVE** — 94 lines (expanding) | [carkeys.blackroad.io](https://carkeys.blackroad.io)

## How It Powers The BlackRoad

CarKeys is the ignition. Every other product starts only after CarKeys authenticates you. No keys, no ride — and your keys are always exactly where you left them.

---

Part of [BlackRoad OS](https://blackroad.io) — Remember the Road. Pave Tomorrow.
