# Fugue

**Security-first AI agent gateway.**

Fugue is a minimal, auditable alternative to bloated AI agent gateways. It connects LLM providers (Ollama, Anthropic, OpenAI) to messaging channels (Telegram, Signal, Discord, CLI) with WASM-sandboxed plugins, encrypted credential storage, and zero network exposure by default.

## Why Fugue?

- **~14,500 lines of Rust** — small enough to audit in a week
- **No WebSocket/HTTP server by default** — zero network attack surface
- **Channel adapters as separate OS processes** — crash isolation
- **WASM-sandboxed plugins** — capability-gated, hash-verified
- **Credentials never in config files** — OS keyring or AES-256-GCM encrypted vault
- **Localhost-only by default** — network exposure requires explicit opt-in

## Architecture

```
          ┌──────────────────────┐
          │   fugue (binary)     │
          │                      │
          │  Config Manager      │  ← TOML (~/.config/fugue/)
          │  Credential Vault    │  ← AES-256-GCM encrypted
          │  Message Router      │  ← Core routing engine
          │  WASM Plugin RT      │  ← Capability-gated
          │  State Store         │  ← SQLite
          │  Audit Log           │  ← Append-only
          └──┬─────────────┬─────┘
             │             │
        Unix Socket    Unix Socket
             │             │
       ┌─────┴──┐    ┌────┴─────┐
       │Telegram │    │ Discord  │
       │Adapter  │    │ Adapter  │
       └─────────┘    └──────────┘
```

## Quick Start

```bash
fugue config init        # Generate default config
fugue vault set my-key   # Store a credential
fugue chat               # Start chatting
```
